// M5 — POST /v1/wallets/recover.
//
// Purpose: a user reinstalling the wallet (new device, lost phone, fresh
// install) regenerates a fresh BabyJubjub keypair and re-runs /v1/wallets/
// register, then proves ownership of an existing ZK nullifier here. The
// nullifier is the durable, device-independent anchor: it is the Poseidon
// hash of the passport's DG15 fields plus event_id, so the same passport
// produces the same nullifier across devices.
//
// Trust model:
//
//   - The fresh ZK proof is sufficient evidence that the user controls the
//     same passport as before. App-attestation already gated the wallet
//     registration, so we know the new wallet sits inside a verified app
//     instance.
//
//   - We do NOT require the user to sign with the old wallet's key — that
//     key is presumed lost. The nullifier replaces that signature as the
//     identity continuity proof.
//
//   - We do NOT allow recovery without a fresh proof (no "claim by nullifier
//     hash alone" path) because the nullifier hash leaks from on-chain data
//     and is not secret.
//
// Side effects on success:
//
//   - All `assertions` rows of the old wallet are rebound to the new wallet
//     (history follows the nullifier).
//
//   - All `pairwise_subjects` rows of the old wallet are rebound to the new
//     wallet. Where the new wallet had already minted a pairwise subject for
//     the same client, the new row is discarded and the old subject wins,
//     so RPs continue to see the same `sub` for the user (continuity).
//
//   - A fresh `zk_verified` assertion is inserted under the new wallet, so
//     /v1/tokens/validate immediately reports the recovered identity as
//     verified with a new TTL.
//
// The old wallet row itself is intentionally not deleted; it becomes
// orphaned (no assertions, no pairwise subjects). A future janitor may
// prune unreferenced wallets.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/jomhoor/sso-svc/internal/zkp"
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

type recoverWalletRequest struct {
	// WalletAddress is the NEW wallet's BabyJubjub address (the wallet the
	// user just registered via /v1/wallets/register on this device).
	WalletAddress string   `json:"walletAddress"`
	CircuitID     string   `json:"circuit_id"`
	Proof         string   `json:"proof"`
	PubSignals    []string `json:"pub_signals"`
}

type recoverWalletResponse struct {
	WalletRecovered bool `json:"walletRecovered"`
	// PriorWalletExisted is true iff a previous wallet was found by
	// nullifier. False means this nullifier has never been seen — the
	// client should treat the call as a no-op recovery (a regular
	// /v1/assertions/zk would have done the same thing).
	PriorWalletExisted bool `json:"priorWalletExisted"`
}

// RecoverWallet handles POST /v1/wallets/recover.
func RecoverWallet(w http.ResponseWriter, r *http.Request) {
	v := ZKP(r)
	if !v.Enabled() {
		Log(r).Warn("wallet recovery attempted but zk verifier disabled")
		ape.RenderErr(w, problems.NotFound())
		return
	}

	var req recoverWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "decode body"))...)
		return
	}
	if req.WalletAddress == "" || req.CircuitID == "" || req.Proof == "" || len(req.PubSignals) == 0 {
		ape.RenderErr(w, problems.BadRequest(
			errors.New("walletAddress, circuit_id, proof and pub_signals are required"),
		)...)
		return
	}
	if !v.SupportsCircuit(req.CircuitID) {
		ape.RenderErr(w, problems.BadRequest(
			errors.Errorf("unsupported circuit_id: %s", req.CircuitID),
		)...)
		return
	}

	db := DB(r)

	// 1. New wallet must already exist (registered + attested via
	//    /v1/wallets/register on this device before calling recover).
	newWallet, err := db.Wallets().GetByAddress(req.WalletAddress)
	if err != nil {
		Log(r).WithError(err).Error("lookup new wallet by address")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if newWallet == nil {
		ape.RenderErr(w, problems.BadRequest(
			errors.New("new wallet not registered — call /v1/wallets/register first"),
		)...)
		return
	}

	// 2. Verify the ZK proof — this is the only authority for rebind. The
	//    verifier checks: event_id pin, registration_smt_root valid on-chain,
	//    and the proof verifies against the circuit's on-chain verifier
	//    contract via eth_call.
	res, err := v.VerifyAssertion(r.Context(), req.CircuitID, req.Proof, req.PubSignals)
	if err != nil {
		if errors.Is(err, zkp.ErrUnknownCircuit) {
			ape.RenderErr(w, problems.BadRequest(err)...)
			return
		}
		Log(r).WithError(err).Warn("recovery proof verification failed")
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "verify proof"))...)
		return
	}
	if len(res.NullifierHash) == 0 {
		// Defensive: a verified proof without a nullifier means we cannot
		// anchor recovery. Should not happen given current circuits.
		Log(r).Error("recovery proof verified but nullifier_hash empty")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	// 3. Find the prior wallet (if any) by nullifier_hash. We look at any
	//    assertion ever recorded for this nullifier — expired and revoked
	//    rows still tell us which wallet was once bound to this passport.
	prior, err := db.Assertions().GetLatestByNullifier(res.NullifierHash)
	if err != nil {
		Log(r).WithError(err).Error("lookup prior assertion by nullifier")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	priorWalletExisted := false

	if prior != nil && prior.WalletID != newWallet.ID {
		// 4. Rebind assertions + pairwise_subjects from old → new
		//    transactionally. After this point /v1/tokens/validate calls
		//    for any RP that knew the old wallet will see the new wallet's
		//    pairwise subject continuing the same `sub`.
		if err := db.RebindWallet(prior.WalletID, newWallet.ID); err != nil {
			Log(r).WithError(err).Error("rebind wallet on recovery")
			ape.RenderErr(w, problems.InternalError())
			return
		}
		priorWalletExisted = true
	}

	// 5. Insert a fresh zk_verified assertion under the new wallet so the
	//    recovered identity has a current, non-expired status row. (If a
	//    rebind happened the moved rows are now under newWallet.ID anyway;
	//    this row gives /v1/tokens/validate a clean current TTL.)
	expiresAt := res.ExpiresAt
	if _, err := db.Assertions().Insert(data.Assertion{
		WalletID:      newWallet.ID,
		AssertionType: "zk_verified",
		Status:        true,
		NullifierHash: res.NullifierHash,
		Source:        "sso-svc:zk-recover-v1:" + req.CircuitID,
		ExpiresAt:     &expiresAt,
	}); err != nil {
		Log(r).WithError(err).Error("insert recovery assertion")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(recoverWalletResponse{
		WalletRecovered:    true,
		PriorWalletExisted: priorWalletExisted,
	}); err != nil {
		Log(r).WithError(err).Error("encode recover response")
	}
}
