// M3: Token exchange, validation, and refresh endpoints.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jomhoor/sso-svc/internal/jwt"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

// Exchange handles POST /v1/tokens/exchange (server-to-server, never browser-side).
//
// Body: { code, client_id, client_secret, code_verifier }
//
// Flow:
//  1. Look up and consume the auth code (validates not expired, not already used).
//  2. Verify client_secret against hashed value in sso_clients.
//  3. Verify PKCE: SHA256(code_verifier) == code_challenge stored with the code.
//  4. Look up pairwiseSubject and active assertions for the wallet.
//  5. Issue access + refresh JWTs with sub=pairwiseSubject, zk_verified assertion.
//  6. Return { access_token, refresh_token, expires_in }.
func Exchange(w http.ResponseWriter, r *http.Request) {
	// TODO M3: implement per flow above.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "not implemented"})
}

// Validate handles GET /v1/tokens/validate?token=<jwt>
// Token introspection for clients that prefer server-side verification over local JWKS.
//
// Response: { valid, subject, client_id, assertions: { zk_verified } }
//
// Note: subject is always the pairwiseSubject — never walletAddress.
func Validate(w http.ResponseWriter, r *http.Request) {
	// AuthMiddleware has already validated the JWT and stored the claim in context.
	claim := Claim(r)
	resp := map[string]any{
		"valid":     true,
		"subject":   claim.Subject,
		"client_id": claim.ClientID,
		"assertions": map[string]any{
			// TODO M3: also refresh from DB so revocations are reflected immediately.
			"zk_verified": claim.ZKVerified,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		Log(r).WithError(err).Error("failed to encode validate response")
	}
}

// Refresh handles POST /v1/tokens/refresh
// Issues a new access token from a valid refresh token.
func Refresh(w http.ResponseWriter, r *http.Request) {
	// AuthMiddleware has validated the refresh token and stored the claim in context.
	refreshClaim := Claim(r)

	accessClaim := &jwt.AuthClaim{
		Subject:    refreshClaim.Subject,
		ClientID:   refreshClaim.ClientID,
		Type:       jwt.AccessTokenType,
		ZKVerified: refreshClaim.ZKVerified,
	}

	accessToken, _, err := JWT(r).IssueJWT(accessClaim)
	if err != nil {
		Log(r).WithError(err).Error("failed to issue refreshed access token")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"access_token": accessToken}); err != nil {
		Log(r).WithError(err).Error("failed to encode refresh response")
	}
}
