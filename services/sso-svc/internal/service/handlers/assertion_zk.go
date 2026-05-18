// M5 item 4 — POST /v1/assertions/zk.
//
// The wallet calls this endpoint after generating a Rarimo query proof
// (queryIdentity / queryIdentity_inid_ca / future variants) with
// `event_id = sso_event_id`. The wallet sends a stable `circuit_id` string
// (e.g. "passport_rsa_2048_sha256_e65537", "inid_rsa_2048") identifying
// which circuit it used; sso-svc looks up the matching VK in its registry.
//
// On success an `assertions` row is inserted with assertion_type="zk_verified"
// (uniform across all circuits — RPs see only the boolean), status=true,
// nullifier_hash=<raw 32 bytes>, source="sso-svc:zk-v1:<circuit_id>" for
// audit, and expires_at=now+TTL. The response carries NO assertion data — RPs
// read live status via /v1/tokens/validate (M2.5 privacy boundary).
package handlers

import (
	"encoding/json"
	"net/http"

	zkptypes "github.com/iden3/go-rapidsnark/types"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/jomhoor/sso-svc/internal/zkp"
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

type submitZKAssertionRequest struct {
	WalletAddress string            `json:"walletAddress"`
	CircuitID     string            `json:"circuit_id"`
	Proof         *zkptypes.ZKProof `json:"proof"`
}

// SubmitZKAssertion handles POST /v1/assertions/zk.
func SubmitZKAssertion(w http.ResponseWriter, r *http.Request) {
	v := ZKP(r)
	if !v.Enabled() {
		Log(r).Warn("zk assertion submitted but verifier disabled")
		ape.RenderErr(w, problems.NotFound())
		return
	}

	var req submitZKAssertionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "decode body"))...)
		return
	}
	if req.WalletAddress == "" || req.CircuitID == "" || req.Proof == nil {
		ape.RenderErr(w, problems.BadRequest(errors.New("walletAddress, circuit_id and proof required"))...)
		return
	}
	if !v.SupportsCircuit(req.CircuitID) {
		ape.RenderErr(w, problems.BadRequest(errors.Errorf("unsupported circuit_id: %s", req.CircuitID))...)
		return
	}

	// Wallet must exist (registered via /v1/wallets/register, attestation already
	// verified at that point). We do NOT require an active app_credential here —
	// the proof itself is a strong identity assertion.
	wallet, err := DB(r).Wallets().GetByAddress(req.WalletAddress)
	if err != nil {
		Log(r).WithError(err).Error("lookup wallet by address")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if wallet == nil {
		ape.RenderErr(w, problems.NotFound())
		return
	}

	res, err := v.VerifyAssertion(r.Context(), req.CircuitID, req.Proof)
	if err != nil {
		if errors.Is(err, zkp.ErrUnknownCircuit) {
			ape.RenderErr(w, problems.BadRequest(err)...)
			return
		}
		Log(r).WithError(err).Warn("zk assertion verification failed")
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "verify proof"))...)
		return
	}

	expiresAt := res.ExpiresAt
	if _, err := DB(r).Assertions().Insert(data.Assertion{
		WalletID:      wallet.ID,
		AssertionType: "zk_verified",
		Status:        true,
		NullifierHash: res.NullifierHash,
		// circuit_id captured in source for audit only — never surfaced to RPs.
		Source:    "sso-svc:zk-v1:" + req.CircuitID,
		ExpiresAt: &expiresAt,
	}); err != nil {
		Log(r).WithError(err).Error("insert zk assertion")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	// No body — RP fetches live status via /v1/tokens/validate.
	w.WriteHeader(http.StatusOK)
}
