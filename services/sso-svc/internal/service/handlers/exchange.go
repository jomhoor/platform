// M3: Token exchange, validation, and refresh endpoints.
package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jomhoor/sso-svc/internal/jwt"
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"golang.org/x/crypto/bcrypt"
)

// exchangeRequest is the wire body for POST /v1/tokens/exchange.
// This endpoint is server-to-server — the RP backend calls it directly,
// never from a browser, so client_secret is safe in the body.
type exchangeRequest struct {
	Code         string `json:"code"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CodeVerifier string `json:"code_verifier"`
}

// exchangeResponse is returned on success.
type exchangeResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	// ExpiresIn is seconds until the access token expires (informational).
	ExpiresIn int `json:"expires_in"`
	TokenType string `json:"token_type"`
}

// Exchange handles POST /v1/tokens/exchange (server-to-server, never browser-side).
//
// Flow:
//  1. Consume the auth code (atomic — rejected if used, expired, or not found).
//  2. Verify client_id matches the code.
//  3. Verify client_secret (bcrypt).
//  4. Verify PKCE S256: base64url(SHA256(code_verifier)) == code.CodeChallenge.
//  5. Issue access + refresh JWTs (sub = pairwiseSubject).
//  6. Return { access_token, refresh_token, expires_in, token_type }.
func Exchange(w http.ResponseWriter, r *http.Request) {
	var req exchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "decode body"))...)
		return
	}
	if req.Code == "" || req.ClientID == "" || req.ClientSecret == "" || req.CodeVerifier == "" {
		Log(r).Debugf("exchange: missing required field (code=%t client_id=%t secret=%t verifier=%t)",
			req.Code != "", req.ClientID != "", req.ClientSecret != "", req.CodeVerifier != "")
		ape.RenderErr(w, problems.BadRequest(
			errors.New("code, client_id, client_secret, and code_verifier are required"))...)
		return
	}

	db := DB(r)

	// 1. Atomic consume — prevents replay.
	code, err := db.AuthCodes().Consume(req.Code)
	if err != nil {
		Log(r).WithError(err).Error("consume auth code")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if code == nil {
		Log(r).Debugf("exchange: code not found / expired / already consumed (code_prefix=%s)", safePrefix(req.Code))
		// Deliberately vague to avoid oracle attacks.
		ape.RenderErr(w, problems.BadRequest(errors.New("invalid, expired, or already used code"))...)
		return
	}

	// 2. client_id binding.
	if code.ClientID != req.ClientID {
		Log(r).Debugf("exchange: client_id mismatch (code.client_id=%s req.client_id=%s)", code.ClientID, req.ClientID)
		ape.RenderErr(w, problems.BadRequest(errors.New("client_id mismatch"))...)
		return
	}

	// 3. client_secret verification (bcrypt — constant-time).
	client, err := db.Clients().GetByID(req.ClientID)
	if err != nil {
		Log(r).WithError(err).Error("lookup client for exchange")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if client == nil {
		ape.RenderErr(w, problems.BadRequest(errors.New("unknown client_id"))...)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(req.ClientSecret)); err != nil {
		// Log at info to help with client mis-configuration debugging, but don't leak reason.
		Log(r).WithError(err).Info("client_secret verification failed")
		ape.RenderErr(w, problems.BadRequest(errors.New("invalid client credentials"))...)
		return
	}

	// 4. PKCE S256: base64url(SHA256(verifier)) must equal the stored challenge.
	//    RFC 7636 §4.6 — no padding, URL-safe alphabet.
	sum := sha256.Sum256([]byte(req.CodeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if computed != code.CodeChallenge {
		Log(r).Debugf("exchange: PKCE mismatch (computed_prefix=%s stored_prefix=%s)", safePrefix(computed), safePrefix(code.CodeChallenge))
		ape.RenderErr(w, problems.BadRequest(errors.New("code_verifier does not match code_challenge"))...)
		return
	}

	// 5. Issue tokens. Subject is always the per-RP pairwise subject — never walletAddress.
	issuer := JWT(r)

	accessClaim := &jwt.AuthClaim{
		Subject:  code.PairwiseSubject,
		ClientID: code.ClientID,
		Type:     jwt.AccessTokenType,
	}
	accessToken, exp, err := issuer.IssueJWT(accessClaim)
	if err != nil {
		Log(r).WithError(err).Error("issue access token")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	refreshClaim := &jwt.AuthClaim{
		Subject:  code.PairwiseSubject,
		ClientID: code.ClientID,
		Type:     jwt.RefreshTokenType,
	}
	refreshToken, _, err := issuer.IssueJWT(refreshClaim)
	if err != nil {
		Log(r).WithError(err).Error("issue refresh token")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	expiresIn := int(time.Until(exp).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	w.Header().Set("Content-Type", "application/json")
	// RFC 6749 §5.1 — no caching of token responses.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(exchangeResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    "Bearer",
	}); err != nil {
		Log(r).WithError(err).Error("encode exchange response")
	}
}

// safePrefix returns the first 12 chars of a token, for log correlation
// without leaking the full secret.
func safePrefix(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Validate handles GET /v1/tokens/validate?token=<jwt>
// Token introspection for clients that prefer server-side verification over local JWKS.
//
// Response: { valid, subject, client_id, assertions: { zk_verified } }
//
// Note: subject is always the pairwiseSubject — never walletAddress.
//
// zk_verified is fetched live from the DB so assertion revocations are reflected
// immediately without requiring a new token issuance.
func Validate(w http.ResponseWriter, r *http.Request) {
	// AuthMiddleware has already validated the JWT and stored the claim in context.
	claim := Claim(r)

	// Live zk_verified refresh: pairwise subject → wallet ID → assertion.
	zkVerified := false
	ps, err := DB(r).PairwiseSubjects().GetBySubject(claim.Subject)
	if err != nil {
		Log(r).WithError(err).Warn("validate: lookup pairwise subject")
		// Non-fatal — default to false; validate is the authoritative source, not the token.
	} else if ps != nil {
		assertion, err := DB(r).Assertions().GetByWalletAndType(ps.WalletID, "zk_verified")
		if err != nil {
			Log(r).WithError(err).Warn("validate: lookup zk_verified assertion")
		} else {
			zkVerified = assertion != nil
		}
	}

	resp := map[string]any{
		"valid":     true,
		"subject":   claim.Subject,
		"client_id": claim.ClientID,
		"assertions": map[string]any{
			"zk_verified": zkVerified,
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
		Subject:  refreshClaim.Subject,
		ClientID: refreshClaim.ClientID,
		Type:     jwt.AccessTokenType,
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
