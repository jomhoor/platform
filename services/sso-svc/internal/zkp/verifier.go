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

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// Verifier is the runtime ZK proof checker for POST /v1/assertions/zk.
//
// Each circuit is verified by calling its on-chain verifier contract via
// JSON-RPC eth_call (`verify(bytes,bytes32[])`). This keeps verification
// proving-system agnostic (UltraPlonk for Noir, Groth16 for Circom) and
// pins trust to the same sovereign verifier bytecode our voting contracts
// already use (e.g. NoirTD1Verifier on Rarimo L2).
//
// Safe for concurrent use: state is read-only after construction and the
// stdlib http.Client is concurrency-safe.
type Verifier struct {
	cfg      Config
	ttl      time.Duration
	circuits map[string]*CircuitConfig

	httpClient *http.Client
}

// selectorVerify is the 4-byte function selector for verify(bytes,bytes32[]).
// Computed from the canonical signature so changing the signature here is the
// single source of truth.
var selectorVerify = keccakSelector("verify(bytes,bytes32[])")

// selectorIsRootValid is the 4-byte function selector for isRootValid(bytes32).
var selectorIsRootValid = keccakSelector("isRootValid(bytes32)")

func keccakSelector(sig string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(sig))
	return h.Sum(nil)[:4]
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

// NewVerifier validates the config and returns a ready Verifier. Errors here
// cause sso-svc to fail-fast at boot — desired.
func NewVerifier(cfg Config) (*Verifier, error) {
	v := &Verifier{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		circuits:   make(map[string]*CircuitConfig),
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

	if cfg.RPCURL == "" {
		return nil, errors.New("zkp enabled but rpc_url not set (required for on-chain verifier calls)")
	}
	if len(cfg.Circuits) == 0 {
		return nil, errors.New("zkp enabled but no circuits configured")
	}

	for id, cc := range cfg.Circuits {
		if cc.VerifierAddress == "" {
			return nil, errors.Errorf("circuit %q missing verifier_address", id)
		}
		ccCopy := cc // capture
		v.circuits[id] = &ccCopy
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
//     on-chain RegistrationSMT (skipped when RegistrationSMTAddr is empty).
//  5. The proof verifies on-chain via verify(bytes,bytes32[]) eth_call.
//  6. Extract nullifier from pub_signals[nullifier_index].
//
// pubSignals accepts decimal ("123…") or hex ("0xabc…" / "abc…") encodings.
// proofHex is the raw `bytes` payload the verifier contract expects.
func (v *Verifier) VerifyAssertion(ctx context.Context, circuitID, proofHex string, pubSignals []string) (*Result, error) {
	if !v.cfg.Enabled {
		return nil, errors.New("zkp verifier disabled")
	}
	if strings.TrimSpace(proofHex) == "" {
		return nil, errors.New("empty proof")
	}

	cc, ok := v.circuits[circuitID]
	if !ok {
		return nil, errors.Wrapf(ErrUnknownCircuit, "circuit_id %q", circuitID)
	}

	if len(pubSignals) <= maxIndex(cc.NullifierIndex, cc.EventIDIndex, cc.SMTRootIndex) {
		return nil, errors.Errorf("pub_signals too short: got %d", len(pubSignals))
	}

	// Parse all pub_signals up-front; we need them both as big.Int (for index
	// comparisons) and as 32-byte words (for the verifier ABI encoding).
	pubInts := make([]*big.Int, len(pubSignals))
	for i, s := range pubSignals {
		n, err := parseFieldElement(s)
		if err != nil {
			return nil, errors.Wrapf(err, "pub_signals[%d]", i)
		}
		pubInts[i] = n
	}

	// 1. Pin event_id before doing the (expensive) on-chain verifier call.
	expectedEventID, ok := new(big.Int).SetString(v.cfg.EventID, 10)
	if !ok {
		return nil, errors.Errorf("config event_id is not a decimal: %s", v.cfg.EventID)
	}
	if pubInts[cc.EventIDIndex].Cmp(expectedEventID) != 0 {
		return nil, errors.Errorf("event_id mismatch: expected %s, got %s",
			expectedEventID.String(), pubInts[cc.EventIDIndex].String())
	}

	// 2. Optional on-chain SMT-root binding.
	if v.cfg.RegistrationSMTAddr != "" {
		root := pubInts[cc.SMTRootIndex]
		ok, err := v.isRootValid(ctx, root)
		if err != nil {
			return nil, errors.Wrap(err, "registration smt root check")
		}
		if !ok {
			return nil, errors.Errorf("registration_smt_root %s is not a valid recent root", root.String())
		}
	}

	// 3. On-chain proof verification.
	proofBytes, err := decodeHexBlob(proofHex)
	if err != nil {
		return nil, errors.Wrap(err, "decode proof hex")
	}
	if err := v.verifyOnChain(ctx, cc.VerifierAddress, proofBytes, pubInts); err != nil {
		return nil, errors.Wrap(err, "on-chain verify")
	}

	// 4. Extract nullifier as a 32-byte big-endian buffer for DB storage.
	buf := make([]byte, 32)
	pubInts[cc.NullifierIndex].FillBytes(buf)

	return &Result{
		NullifierHash: buf,
		ExpiresAt:     time.Now().UTC().Add(v.ttl),
	}, nil
}

// verifyOnChain ABI-encodes verify(bytes,bytes32[]) and eth_calls the circuit's
// on-chain verifier contract. The contract returns true on success or reverts
// on failure; we treat any RPC error or non-true result as a failed proof.
func (v *Verifier) verifyOnChain(ctx context.Context, verifierAddr string, proof []byte, pubSignals []*big.Int) error {
	calldata := encodeVerifyCalldata(proof, pubSignals)
	resultHex, err := v.ethCall(ctx, verifierAddr, "0x"+hex.EncodeToString(calldata))
	if err != nil {
		return err
	}
	out := strings.TrimPrefix(resultHex, "0x")
	if len(out) != 64 {
		return errors.Errorf("unexpected verify() return length %d (raw=%s)", len(out), resultHex)
	}
	if out[63] != '1' {
		return errors.Errorf("verify() returned false (raw=%s)", resultHex)
	}
	return nil
}

// encodeVerifyCalldata builds calldata for verify(bytes _proof, bytes32[] _publicInputs).
//
// ABI layout (after the 4-byte selector):
//
//	0x00: offset to _proof         = 0x40
//	0x20: offset to _publicInputs  = 0x40 + 32 + paddedLen(_proof)
//	0x40: len(_proof)
//	0x60: _proof bytes, padded to a 32-byte multiple
//	...:  len(_publicInputs)
//	...:  each public input as bytes32
func encodeVerifyCalldata(proof []byte, pubSignals []*big.Int) []byte {
	proofLen := len(proof)
	paddedLen := (proofLen + 31) / 32 * 32

	var buf bytes.Buffer
	buf.Write(selectorVerify)

	writeUint256(&buf, big.NewInt(0x40))
	pubOffset := int64(0x40 + 32 + paddedLen)
	writeUint256(&buf, big.NewInt(pubOffset))

	writeUint256(&buf, big.NewInt(int64(proofLen)))
	buf.Write(proof)
	if pad := paddedLen - proofLen; pad > 0 {
		buf.Write(make([]byte, pad))
	}

	writeUint256(&buf, big.NewInt(int64(len(pubSignals))))
	for _, n := range pubSignals {
		writeUint256(&buf, n)
	}
	return buf.Bytes()
}

func writeUint256(buf *bytes.Buffer, n *big.Int) {
	word := make([]byte, 32)
	n.FillBytes(word)
	buf.Write(word)
}

// parseFieldElement accepts decimal ("123…") or hex ("0xabc…" / "abc…") and
// returns the big.Int value with no field-modulus reduction.
func parseFieldElement(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") || containsNonDigit(s) {
		hexPart := strings.TrimPrefix(s, "0x")
		hexPart = strings.TrimPrefix(hexPart, "0X")
		n, ok := new(big.Int).SetString(hexPart, 16)
		if !ok {
			return nil, errors.Errorf("invalid hex: %s", s)
		}
		return n, nil
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, errors.Errorf("invalid decimal: %s", s)
	}
	return n, nil
}

func containsNonDigit(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return true
		}
	}
	return false
}

func decodeHexBlob(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

// ethCall is the shared JSON-RPC plumbing for view-only contract calls.
func (v *Verifier) ethCall(ctx context.Context, to, dataHex string) (string, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []interface{}{
			map[string]string{"to": to, "data": dataHex},
			"latest",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", errors.Wrap(err, "marshal eth_call")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", v.cfg.RPCURL, bytes.NewReader(body))
	if err != nil {
		return "", errors.Wrap(err, "build rpc request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "rpc request")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "read rpc body")
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("rpc status %d: %s", resp.StatusCode, string(respBody))
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", errors.Wrap(err, "decode rpc body")
	}
	if rpcResp.Error != nil {
		return "", errors.Errorf("rpc error: %s", rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

// isRootValid calls RegistrationSMT.isRootValid(bytes32) via eth_call.
func (v *Verifier) isRootValid(ctx context.Context, root *big.Int) (bool, error) {
	rootBuf := make([]byte, 32)
	root.FillBytes(rootBuf)

	data := "0x" + hex.EncodeToString(selectorIsRootValid) + hex.EncodeToString(rootBuf)
	resultHex, err := v.ethCall(ctx, v.cfg.RegistrationSMTAddr, data)
	if err != nil {
		return false, err
	}
	out := strings.TrimPrefix(resultHex, "0x")
	if len(out) != 64 {
		return false, errors.Errorf("unexpected return length %d (raw=%s)", len(out), resultHex)
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
