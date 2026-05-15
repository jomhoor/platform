// Package handlers — M2: Wallet registration challenge and registration.
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jomhoor/sso-svc/internal/crypto"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

// WalletChallenge issues a short-lived nonce for wallet registration.
//
// POST /v1/wallets/challenge
// Body: { "platform": "ios" | "android" }
// Response: { "challenge": "0x<64hex>", "expires_at": "<RFC3339>" }
func WalletChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "decode body"))...)
		return
	}
	if req.Platform != "ios" && req.Platform != "android" {
		ape.RenderErr(w, problems.BadRequest(errors.New("platform must be 'ios' or 'android'"))...)
		return
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		Log(r).WithError(err).Error("failed to generate random nonce")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	nonceHex := "0x" + hex.EncodeToString(nonce)
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	if err := DB(r).WalletChallenges().Insert(data.WalletChallenge{
		Nonce:     nonceHex,
		Platform:  req.Platform,
		ExpiresAt: expiresAt,
	}); err != nil {
		Log(r).WithError(err).Error("failed to insert wallet challenge")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"challenge":  nonceHex,
		"expires_at": expiresAt.Format(time.RFC3339),
	}); err != nil {
		Log(r).WithError(err).Error("failed to encode challenge response")
	}
}

// registerRequest is the wire format for POST /v1/wallets/register.
type registerRequest struct {
	WalletAddress  string          `json:"walletAddress"`
	PublicKey      publicKeyFields `json:"publicKey"`
	Challenge      string          `json:"challenge"`
	WalletSignature string         `json:"walletSignature"`
	// AppAttestation is platform-specific. Ignored when attestation is disabled.
	AppAttestation json.RawMessage `json:"appAttestation"`
}

type publicKeyFields struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// RegisterWallet stores a new wallet with a verified app credential.
//
// POST /v1/wallets/register
// Body: registerRequest (see above)
// Response: { "walletRegistered": true }
//
// Verification steps (all must pass):
//  1. Parse and validate request body.
//  2. Consume the registration challenge nonce (atomic, prevents replay).
//  3. Verify poseidon([publicKey.x, publicKey.y]) == walletAddress.
//  4. Verify walletSignature over the challenge.
//  5. If attestation.Enabled: verify platform attestation (iOS App Attest / Android Play Integrity).
//     When disabled (local dev), skip attestation — credential is stored with status "verified".
//  6. Revoke any existing active credential for wallet+platform.
//  7. Insert wallet row (or reuse existing) + app_credential row.
func RegisterWallet(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "decode body"))...)
		return
	}

	if req.WalletAddress == "" || req.PublicKey.X == "" || req.PublicKey.Y == "" ||
		req.Challenge == "" || req.WalletSignature == "" {
		ape.RenderErr(w, problems.BadRequest(errors.New("walletAddress, publicKey.{x,y}, challenge, and walletSignature are required"))...)
		return
	}

	// 1. Consume the registration nonce atomically — prevents replay.
	challenge, err := DB(r).WalletChallenges().Consume(req.Challenge)
	if err != nil {
		Log(r).WithError(err).Error("consume wallet challenge")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if challenge == nil {
		Log(r).Error("register: challenge not found, expired, or already used")
		ape.RenderErr(w, problems.BadRequest(errors.New("challenge not found, expired, or already used"))...)
		return
	}

	// 2. Verify poseidon([publicKey.x, publicKey.y]) == walletAddress.
	if err := crypto.VerifyWalletAddress(req.PublicKey.X, req.PublicKey.Y, req.WalletAddress); err != nil {
		Log(r).WithError(err).Error("register: wallet address mismatch")
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "wallet address mismatch"))...)
		return
	}

	// 3. Verify EdDSA signature over the challenge.
	if err := crypto.VerifyWalletSignature(req.PublicKey.X, req.PublicKey.Y, req.Challenge, req.WalletSignature); err != nil {
		Log(r).WithError(err).Error("register: invalid wallet signature")
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "invalid wallet signature"))...)
		return
	}

	// 4. App attestation gate.
	attest := Attestation(r)
	credentialID := "local-dev"
	attestationKeyID := ""
	if attest.Enabled {
		// TODO M2.attestation: verify platform attestation.
		// iOS: verify Apple App Attest certificate chain (team_id, bundle_id, challenge binding, key consistency).
		// Android: verify Play Integrity token (package_name, signing_cert_digests, verdict, challenge binding).
		// On failure: ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "app attestation failed"))...)
		ape.RenderErr(w, problems.BadRequest(errors.New("app attestation verification not yet implemented"))...)
		return
	}

	db := DB(r)

	// 5. Look up existing wallet or insert a new one.
	wallet, err := db.Wallets().GetByAddress(req.WalletAddress)
	if err != nil {
		Log(r).WithError(err).Error("lookup wallet by address")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if wallet == nil {
		created, err := db.Wallets().Insert(data.Wallet{
			WalletAddress: req.WalletAddress,
			PublicKeyX:    req.PublicKey.X,
			PublicKeyY:    req.PublicKey.Y,
		})
		if err != nil {
			Log(r).WithError(err).Error("insert wallet")
			ape.RenderErr(w, problems.InternalError())
			return
		}
		wallet = &created
	}

	// 6. Revoke any previous credential for this wallet+platform (re-install path).
	if err := db.AppCredentials().RevokeByWallet(wallet.ID, challenge.Platform); err != nil {
		Log(r).WithError(err).Error("revoke existing credentials")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	// 7. Store the new verified credential.
	if _, err := db.AppCredentials().Insert(data.AppCredential{
		WalletID:          wallet.ID,
		Platform:          challenge.Platform,
		CredentialID:      credentialID,
		AttestationKeyID:  attestationKeyID,
		AttestationStatus: "verified",
	}); err != nil {
		Log(r).WithError(err).Error("insert app credential")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"walletRegistered": true}); err != nil {
		Log(r).WithError(err).Error("failed to encode register response")
	}
}
