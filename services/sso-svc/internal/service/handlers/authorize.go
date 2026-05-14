// M3: OAuth2 auth-code + PKCE authorization endpoint.
// Validates the client, creates a login challenge, and redirects the browser
// to the Universal Link that opens the Jomhoor wallet app.
package handlers

import (
	"encoding/json"
	"net/http"
)

// Authorize handles GET /v1/authorize
//
// Query params: client_id, redirect_uri, state, code_challenge, code_challenge_method=S256
//
// Flow:
//  1. Validate client_id exists in sso_clients.
//  2. Validate redirect_uri is in client's allow-list (exact match).
//  3. Store { nonce, client_id, redirect_uri, state, code_challenge, expires_at=+5min }.
//  4. Build deep link: jomhoor://auth/sso?challenge=<nonce>&client_id=X&state=Y
//     Primary: https://sso.jomhoor.org/auth/sso?... (Universal Link — app intercepts)
//     Fallback: jomhoor://auth/sso?... (custom scheme for local/sideloaded builds)
//  5. 302 redirect to deep link.
func Authorize(w http.ResponseWriter, r *http.Request) {
	// TODO M3: implement per flow above.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "not implemented"})
}

// Verify handles POST /v1/authorize/verify
// Called by the app after the user approves the consent screen.
//
// Body: { challenge, walletAddress, signature, appAssertion }
//
// Flow:
//  1. Consume the challenge nonce (marks it used, validates not expired).
//  2. Look up wallet by walletAddress → get publicKey {x, y}.
//  3. Verify EdDSA signature(challenge, publicKey).
//  4. Verify app assertion against stored app credential (re-validates device trust on each login).
//  5. Check if client has zkRequired=true; if so, verify zk_verified assertion exists.
//  6. Derive or look up pairwiseSubject = Pairwise(r).Derive(walletID, clientID).
//  7. Upsert pairwise_subjects row.
//  8. Issue one-time auth code bound to { pairwiseSubject, client_id, code_challenge }.
//  9. Redirect: redirect_uri?code=<code>&state=<state>
func Verify(w http.ResponseWriter, r *http.Request) {
	// TODO M3: implement per flow above.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "not implemented"})
}
