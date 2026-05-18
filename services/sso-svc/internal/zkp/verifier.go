package zkp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	zkptypes "github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/pkg/errors"
)

// loadedCircuit is the runtime form of a CircuitConfig with VK bytes resolved.
type loadedCircuit struct {
	cfg CircuitConfig
	vk  []byte
}

// Verifier is the runtime ZK proof checker for POST /v1/assertions/zk.
//
// Constructed once at startup with all configured circuits' VKs pre-loaded.
// Safe for concurrent use: Groth16 verification is pure; the HTTP RPC client
// is concurrency-safe by stdlib contract.
type Verifier struct {
	cfg      Config
	ttl      time.Duration
	circuits map[string]*loadedCircuit

	httpClient *http.Client
}

// Result is the successful outcome of VerifyAssertion. NullifierHash is the
// raw 32-byte big-endian encoding of the nullifier field element, ready for
// the assertions.nullifier_hash column.
type Result struct {
	NullifierHash []byte
	ExpiresAt     time.Time
}

// ErrUnknownCircuit is returned when the wallet sends a circuit_id that is
// not in the configured registry. Handler maps it to 400 with a clear message
// so the wallet can fall back to a different document or surface an error.
var ErrUnknownCircuit = errors.New("unknown circuit_id")

// NewVerifier validates the config, loads all VKs from disk, and returns a
// ready Verifier. Errors here cause sso-svc to fail-fast at boot — desired.
func NewVerifier(cfg Config) (*Verifier, error) {
	v := &Verifier{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		circuits:   make(map[string]*loadedCircuit),
	}

	if !cfg.Enabled {
		// Allow boot in disabled mode; the handler will return 404.
		return v, nil
	}

	ttl, err := time.ParseDuration(cfg.AssertionTTL)
	if err != nil {
		return nil, errors.Wrap(err, "parse assertion_ttl")
	}
	v.ttl = ttl

	if len(cfg.Circuits) == 0 {
		return nil, errors.New("zkp enabled but no circuits configured")
	}

	for id, cc := range cfg.Circuits {
		vk, err := cc.LoadVerificationKey()
		if err != nil {
			return nil, errors.Wrapf(err, "load vk for circuit %q", id)
		}
		ccCopy := cc // capture
		v.circuits[id] = &loadedCircuit{cfg: ccCopy, vk: vk}
	}

	return v, nil
}

// Enabled reports whether the handler should accept proofs.
func (v *Verifier) Enabled() bool { return v.cfg.Enabled }

// SupportsCircuit reports whether `circuitID` is in the configured registry.
// Useful for fast pre-flight 400s in the handler.
func (v *Verifier) SupportsCircuit(circuitID string) bool {
	_, ok := v.circuits[circuitID]
	return ok
}

// VerifyAssertion runs the full check pipeline for the named circuit:
//
//  1. circuit_id is in the registry.
//  2. pub_signals length matches the configured index layout.
//  3. pub_signals[event_id_index] equals the configured global event_id.
//  4. Optionally: pub_signals[smt_root_index] is a recent valid root in the
//     on-chain RegistrationSMT (skipped when RPCURL is empty).
//  5. Groth16 proof verifies against the per-circuit pinned VK.
//  6. Extract nullifier from pub_signals[nullifier_index].
//
// Returns Result with the raw 32-byte nullifier and the assertion expiry.
func (v *Verifier) VerifyAssertion(ctx context.Context, circuitID string, proof *zkptypes.ZKProof) (*Result, error) {
	if !v.cfg.Enabled {
		return nil, errors.New("zkp verifier disabled")
	}
	if proof == nil {
		return nil, errors.New("nil proof")
	}

	lc, ok := v.circuits[circuitID]
	if !ok {
		return nil, errors.Wrapf(ErrUnknownCircuit, "circuit_id %q", circuitID)
	}
	cc := lc.cfg

	if len(proof.PubSignals) <= maxIndex(cc.NullifierIndex, cc.EventIDIndex, cc.SMTRootIndex) {
		return nil, errors.Errorf("pub_signals too short: got %d", len(proof.PubSignals))
	}

	// 1. Pin event_id before doing expensive proof verification.
	if got := proof.PubSignals[cc.EventIDIndex]; got != v.cfg.EventID {
		return nil, errors.Errorf("event_id mismatch: expected %s, got %s", v.cfg.EventID, got)
	}

	// 2. Optional on-chain SMT-root binding.
	if v.cfg.RPCURL != "" && v.cfg.RegistrationSMTAddr != "" {
		rootDec := proof.PubSignals[cc.SMTRootIndex]
		ok, err := v.isRootValid(ctx, rootDec)
		if err != nil {
			return nil, errors.Wrap(err, "registration smt root check")
		}
		if !ok {
			return nil, errors.Errorf("registration_smt_root %s is not a valid recent root", rootDec)
		}
	}

	// 3. Groth16 verification against this circuit's VK.
	if err := verifier.VerifyGroth16(*proof, lc.vk); err != nil {
		return nil, errors.Wrap(err, "groth16 verify")
	}

	// 4. Extract nullifier as a 32-byte big-endian buffer for DB storage.
	nullifierDec := proof.PubSignals[cc.NullifierIndex]
	n, ok := new(big.Int).SetString(nullifierDec, 10)
	if !ok {
		return nil, errors.Errorf("invalid nullifier decimal: %s", nullifierDec)
	}
	buf := make([]byte, 32)
	n.FillBytes(buf)

	return &Result{
		NullifierHash: buf,
		ExpiresAt:     time.Now().UTC().Add(v.ttl),
	}, nil
}

// isRootValid calls RegistrationSMT.isRootValid(bytes32) via JSON-RPC eth_call.
// We avoid pulling in go-ethereum just for one view call: hand-roll the ABI
// encoding (4-byte selector + bytes32) and decode the boolean from the 32-byte
// return.
//
// Selector for `isRootValid(bytes32)` is the first 4 bytes of
// keccak256("isRootValid(bytes32)") = 0x71f6a410.
func (v *Verifier) isRootValid(ctx context.Context, rootDec string) (bool, error) {
	root, ok := new(big.Int).SetString(rootDec, 10)
	if !ok {
		return false, errors.Errorf("invalid root decimal: %s", rootDec)
	}
	rootBuf := make([]byte, 32)
	root.FillBytes(rootBuf)

	const selectorIsRootValid = "71f6a410"
	data := "0x" + selectorIsRootValid + hex.EncodeToString(rootBuf)

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []interface{}{
			map[string]string{
				"to":   v.cfg.RegistrationSMTAddr,
				"data": data,
			},
			"latest",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, errors.Wrap(err, "marshal eth_call")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", v.cfg.RPCURL, bytes.NewReader(body))
	if err != nil {
		return false, errors.Wrap(err, "build rpc request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, errors.Wrap(err, "rpc request")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "read rpc body")
	}
	if resp.StatusCode != http.StatusOK {
		return false, errors.Errorf("rpc status %d: %s", resp.StatusCode, string(respBody))
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return false, errors.Wrap(err, "decode rpc body")
	}
	if rpcResp.Error != nil {
		return false, errors.Errorf("rpc error: %s", rpcResp.Error.Message)
	}

	// Boolean return: last byte of the 32-byte word is 0x01 (true) or 0x00 (false).
	out := strings.TrimPrefix(rpcResp.Result, "0x")
	if len(out) != 64 {
		return false, errors.Errorf("unexpected return length %d (raw=%s)", len(out), rpcResp.Result)
	}
	return out[63] == '1', nil
}

func maxIndex(xs ...int) int {
	m := 0
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}
