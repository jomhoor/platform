// M2: Wallet registration challenge.
// Issues a short-lived nonce that the app must sign and include with app attestation
// material in POST /v1/wallets/register.
package handlers

import (
	"encoding/json"
	"net/http"
)

// WalletChallenge issues a short-lived nonce for wallet registration.
// M2 implementation: generate secure random nonce, store in sso_challenges, return to app.
//
// POST /v1/wallets/challenge
// Body: { "platform": "ios" | "android" }
func WalletChallenge(w http.ResponseWriter, r *http.Request) {
	// TODO M2: parse platform, generate nonce, store in sso_challenges, return JSON.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "not implemented"})
}

// RegisterWallet stores a new wallet with verified app credentials.
// Hard gate: if app attestation fails or is disabled, return 403.
//
// POST /v1/wallets/register
// Body: { walletAddress, publicKey: {x, y}, challenge, walletSignature, appAttestation: {...} }
func RegisterWallet(w http.ResponseWriter, r *http.Request) {
	// TODO M2:
	//   1. Parse and validate request body.
	//   2. Check attestation.Enabled; if disabled in prod, return 403.
	//   3. Verify walletSignature(challenge, publicKey).
	//   4. Verify appAttestation (iOS App Attest or Android Play Integrity).
	//   5. Assert poseidon([x, y]) == walletAddress.
	//   6. Revoke any existing active credential for wallet+platform.
	//   7. Insert wallet + app_credential rows.
	//   8. Return { "walletRegistered": true }.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "not implemented"})
}
