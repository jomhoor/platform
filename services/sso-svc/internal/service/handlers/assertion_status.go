// M5 item 1: Pre-flight ZK assertion check.
//
// The wallet calls GET /v1/wallets/{address}/assertions/zk before showing the
// consent screen when an RP advertises `zk_required=true`. This lets the
// wallet decide UP FRONT whether to:
//   - proceed straight to consent + sign (assertion already live), or
//   - route the user through the ZK escalation screen first.
//
// Without this endpoint the wallet would optimistically sign, hit a 403 from
// /v1/authorize/verify, and have nothing useful to show the user.
//
// SECURITY:
//   - Unauthenticated by design. The wallet address is a public identifier
//     and the only fields returned are a boolean and an expiry timestamp.
//   - We do NOT return the nullifier hash, the assertion source, or any other
//     value that could be used to correlate wallets across RPs.
//   - Unknown wallet → 404 (same shape as GetClient). We intentionally do not
//     leak the difference between "no such wallet" and "wallet has no assertion"
//     here to keep this endpoint usable only by callers who already know the
//     wallet address.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

type zkAssertionStatusResponse struct {
	Valid     bool       `json:"valid"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// GetZKAssertionStatus handles GET /v1/wallets/{address}/assertions/zk.
//
// Returns {valid: false} for a known wallet with no live zk_verified assertion,
// {valid: true, expires_at: ...} when one exists. 404 for unknown wallets so
// the wallet app can distinguish a misrouted request from a missing assertion.
func GetZKAssertionStatus(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimSpace(chi.URLParam(r, "address"))
	if addr == "" {
		ape.RenderErr(w, problems.BadRequest(errors.New("wallet address required"))...)
		return
	}

	wallet, err := DB(r).Wallets().GetByAddress(addr)
	if err != nil {
		Log(r).WithError(err).Error("lookup wallet for zk assertion status")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if wallet == nil {
		ape.RenderErr(w, problems.NotFound())
		return
	}

	assertion, err := DB(r).Assertions().GetByWalletAndType(wallet.ID, "zk_verified")
	if err != nil {
		Log(r).WithError(err).Error("lookup zk assertion")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	resp := zkAssertionStatusResponse{Valid: assertion != nil}
	if assertion != nil {
		resp.ExpiresAt = assertion.ExpiresAt
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		Log(r).WithError(err).Error("encode zk assertion status response")
	}
}
