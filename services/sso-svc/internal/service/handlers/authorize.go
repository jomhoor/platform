// M3: OAuth2 auth-code + PKCE authorization endpoints.
//
// Two-step flow:
//
//   1. RP browser  → GET  /v1/authorize ............. (this file: Authorize)
//      sso-svc allocates a nonce + stores PKCE state, then 302s the browser
//      to the wallet-app deep link. Universal Link / App Link opens the app.
//
//   2. Wallet app  → POST /v1/authorize/verify ...... (this file: Verify)
//      The user has approved the consent screen. The app posts the signed
//      challenge + (eventually) an app assertion. sso-svc verifies, derives
//      the pairwise subject for this RP, mints a one-time auth code, and
//      returns the redirect URL the app should hand back to the browser.
//
//   3. RP server   → POST /v1/tokens/exchange ....... (exchange.go)
//      Exchanges the auth code + PKCE verifier for access + refresh JWTs.
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jomhoor/sso-svc/internal/crypto"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

// challengeTTL is how long a /v1/authorize nonce is valid before the wallet app
// must complete the verify step. Short enough to limit replay window, long
// enough to cover a slow user and slow Universal-Link routing.
const challengeTTL = 5 * time.Minute

// authCodeTTL is how long the issued auth code is valid before the RP must
// exchange it for tokens. RFC 6749 §4.1.2 recommends ~10 minutes max; we use
// 2 minutes since the RP's server-to-server exchange should be near-instant.
const authCodeTTL = 2 * time.Minute

// Authorize handles GET /v1/authorize.
//
// Query params: client_id, redirect_uri, state, code_challenge, code_challenge_method=S256
//
// Validates the client + redirect_uri, allocates a nonce, persists the PKCE
// challenge against it, and 302-redirects the browser to the wallet-app
// Universal Link with `?challenge=<nonce>&client_id=…&state=…`.
func Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")

	if clientID == "" || redirectURI == "" || state == "" || codeChallenge == "" {
		ape.RenderErr(w, problems.BadRequest(
			errors.New("client_id, redirect_uri, state, and code_challenge are required"))...)
		return
	}
	// Only S256 is supported. `plain` is an OAuth2 footgun (downgrade attack on
	// the verifier transport), so we refuse it explicitly.
	if method != "S256" {
		ape.RenderErr(w, problems.BadRequest(
			errors.New("code_challenge_method must be S256"))...)
		return
	}

	client, err := DB(r).Clients().GetByID(clientID)
	if err != nil {
		Log(r).WithError(err).Error("lookup sso client")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if client == nil {
		ape.RenderErr(w, problems.BadRequest(errors.New("unknown client_id"))...)
		return
	}

	// Exact match against the allow-list. RFC 6749 §3.1.2 — no prefix matching,
	// no wildcards. This blocks open-redirect attacks via crafted redirect_uri.
	if !contains(client.RedirectURIs, redirectURI) {
		ape.RenderErr(w, problems.BadRequest(errors.New("redirect_uri not allowed for client"))...)
		return
	}

	nonce, err := randomHex(32)
	if err != nil {
		Log(r).WithError(err).Error("generate authorize nonce")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	expiresAt := time.Now().UTC().Add(challengeTTL)
	if err := DB(r).Challenges().Insert(data.SSOChallenge{
		Nonce:         nonce,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		State:         state,
		CodeChallenge: codeChallenge,
		ExpiresAt:     expiresAt,
	}); err != nil {
		Log(r).WithError(err).Error("insert sso challenge")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	// Build the Universal Link target. The app is the only consumer of these
	// query params — the browser sees the URL only as a Location header.
	dl := Deeplink(r)
	deepLink, err := url.Parse(dl.UniversalLinkBase)
	if err != nil {
		Log(r).WithError(err).Error("parse deeplink universal_link_base")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	dq := deepLink.Query()
	dq.Set("challenge", nonce)
	dq.Set("client_id", clientID)
	dq.Set("state", state)
	// Pass the server's own public URL so the app always calls back to the
	// correct host regardless of its build-time env config. Infer scheme from
	// TLS state and X-Forwarded-Proto; host from the request Host header.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	dq.Set("api_url", scheme+"://"+r.Host)
	deepLink.RawQuery = dq.Encode()

	http.Redirect(w, r, deepLink.String(), http.StatusFound)
}

// verifyRequest is the wire format for POST /v1/authorize/verify.
type verifyRequest struct {
	Challenge       string `json:"challenge"`
	WalletAddress   string `json:"walletAddress"`
	WalletSignature string `json:"walletSignature"`
	// AppAssertion is platform-specific. Currently optional — re-enabled
	// alongside M2b's attestation rollout (see plan.txt M2b checklist).
	AppAssertion json.RawMessage `json:"appAssertion"`
}

// verifyResponse tells the wallet app where to send the user's browser next.
// The app does not perform the redirect itself; the browser session is on the
// RP's domain and only its Universal-Link / Custom-Tab can complete it.
type verifyResponse struct {
	RedirectURL string `json:"redirect_url"`
}

// Verify handles POST /v1/authorize/verify.
//
//  1. Atomically consume the challenge (single-use).
//  2. Look up the wallet by walletAddress.
//  3. Verify the BabyJubjub signature over the challenge nonce.
//  4. (M2b) Verify the platform app assertion; today it is accepted as-is.
//  5. If the client requires ZK, check the wallet has a `zk_verified` assertion.
//  6. Derive (and persist) the per-client pairwise subject.
//  7. Mint a one-time auth code bound to {client, subject, code_challenge, zk}.
//  8. Return the redirect URL `redirect_uri?code=<code>&state=<state>`.
func Verify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "decode body"))...)
		return
	}
	if req.Challenge == "" || req.WalletAddress == "" || req.WalletSignature == "" {
		Log(r).WithFields(map[string]interface{}{
			"challenge_empty":   req.Challenge == "",
			"address_empty":     req.WalletAddress == "",
			"signature_empty":   req.WalletSignature == "",
		}).Warn("verify: missing required fields")
		ape.RenderErr(w, problems.BadRequest(
			errors.New("challenge, walletAddress, and walletSignature are required"))...)
		return
	}

	db := DB(r)

	// 1. Consume the nonce — atomic, replay-safe.
	challenge, err := db.Challenges().Consume(req.Challenge)
	if err != nil {
		Log(r).WithError(err).Error("consume sso challenge")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if challenge == nil {
		Log(r).WithField("challenge", req.Challenge).Warn("verify: challenge not found, expired, or already used")
		ape.RenderErr(w, problems.BadRequest(
			errors.New("challenge not found, expired, or already used"))...)
		return
	}

	// 2. Wallet must already be registered (M2 flow).
	wallet, err := db.Wallets().GetByAddress(req.WalletAddress)
	if err != nil {
		Log(r).WithError(err).Error("lookup wallet")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if wallet == nil {
		Log(r).WithField("wallet_address", req.WalletAddress).Warn("verify: wallet not registered")
		ape.RenderErr(w, problems.BadRequest(errors.New("wallet not registered"))...)
		return
	}

	// 3. Verify BabyJubjub EdDSA signature over the challenge nonce.
	if err := crypto.VerifyWalletSignature(
		wallet.PublicKeyX, wallet.PublicKeyY, req.Challenge, req.WalletSignature,
	); err != nil {
		Log(r).WithError(err).WithFields(map[string]interface{}{
			"wallet_address": req.WalletAddress,
			"challenge":      req.Challenge,
		}).Warn("verify: invalid wallet signature")
		ape.RenderErr(w, problems.BadRequest(errors.Wrap(err, "invalid wallet signature"))...)
		return
	}

	// 4. Platform attestation — wired in M2b.
	//    When attestation is enabled and req.AppAssertion is missing/invalid,
	//    Verify must hard-fail. For now we hard-fail on missing assertion only.
	attest := Attestation(r)
	if attest.Enabled && len(req.AppAssertion) == 0 {
		ape.RenderErr(w, problems.BadRequest(
			errors.New("app assertion required when attestation is enabled (M2b)"))...)
		return
	}

	// 5. Re-load the client so we know whether ZK is required for this RP.
	client, err := db.Clients().GetByID(challenge.ClientID)
	if err != nil {
		Log(r).WithError(err).Error("re-lookup client during verify")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if client == nil {
		ape.RenderErr(w, problems.BadRequest(errors.New("client no longer exists"))...)
		return
	}

	zkVerified := false
	if client.ZKRequired {
		assertion, err := db.Assertions().GetByWalletAndType(wallet.ID, "zk_verified")
		if err != nil {
			Log(r).WithError(err).Error("lookup zk_verified assertion")
			ape.RenderErr(w, problems.InternalError())
			return
		}
		if assertion == nil {
			// Specific error so the app can surface a "verify your identity" CTA.
			Log(r).Warn("client requires zk_verified assertion but wallet has none")
			ape.RenderErr(w, problems.Forbidden())
			return
		}
		zkVerified = true
	} else {
		// Best-effort snapshot: surface the assertion if it exists, but don't gate.
		assertion, err := db.Assertions().GetByWalletAndType(wallet.ID, "zk_verified")
		if err == nil && assertion != nil {
			zkVerified = true
		}
	}

	// 6. Pairwise subject — stable per (wallet, client), unlinkable across clients.
	subject := Pairwise(r).Derive(wallet.ID, client.ID)
	if _, err := db.PairwiseSubjects().Upsert(data.PairwiseSubject{
		WalletID: wallet.ID,
		ClientID: client.ID,
		Subject:  subject,
	}); err != nil {
		Log(r).WithError(err).Error("upsert pairwise subject")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	// 7. Mint the one-time auth code.
	code, err := randomHex(32)
	if err != nil {
		Log(r).WithError(err).Error("generate auth code")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if err := db.AuthCodes().Insert(data.AuthCode{
		Code:            code,
		ClientID:        client.ID,
		PairwiseSubject: subject,
		CodeChallenge:   challenge.CodeChallenge,
		ZKVerified:      zkVerified,
		ExpiresAt:       time.Now().UTC().Add(authCodeTTL),
	}); err != nil {
		Log(r).WithError(err).Error("insert auth code")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	// 8. Build the redirect URL the wallet app should hand to the browser.
	redirect, err := url.Parse(challenge.RedirectURI)
	if err != nil {
		Log(r).WithError(err).Error("parse stored redirect_uri")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", challenge.State)
	redirect.RawQuery = rq.Encode()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(verifyResponse{RedirectURL: redirect.String()}); err != nil {
		Log(r).WithError(err).Error("encode verify response")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.Wrap(err, "read random bytes")
	}
	return "0x" + hex.EncodeToString(buf), nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}
