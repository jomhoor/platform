package data

import (
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Domain types
// ─────────────────────────────────────────────────────────────────────────────

type Wallet struct {
	ID            string    `db:"id"`
	WalletAddress string    `db:"wallet_address"`
	PublicKeyX    string    `db:"public_key_x"`
	PublicKeyY    string    `db:"public_key_y"`
	RegisteredAt  time.Time `db:"registered_at"`
}

type AppCredential struct {
	ID                string    `db:"id"`
	WalletID          string    `db:"wallet_id"`
	Platform          string    `db:"platform"`
	CredentialID      string    `db:"credential_id"`
	AttestationKeyID  string    `db:"attestation_key_id"`
	AttestationStatus string    `db:"attestation_status"`
	AttestedAt        time.Time `db:"attested_at"`
	LastVerifiedAt    time.Time `db:"last_verified_at"`
}

type Assertion struct {
	ID            string     `db:"id"`
	WalletID      string     `db:"wallet_id"`
	AssertionType string     `db:"assertion_type"`
	Status        bool       `db:"status"`
	NullifierHash []byte     `db:"nullifier_hash"`
	Source        string     `db:"source"`
	IssuedAt      time.Time  `db:"issued_at"`
	ExpiresAt     *time.Time `db:"expires_at"`
}

type PairwiseSubject struct {
	ID        string    `db:"id"`
	WalletID  string    `db:"wallet_id"`
	ClientID  string    `db:"client_id"`
	Subject   string    `db:"subject"`
	CreatedAt time.Time `db:"created_at"`
}

type SSOClient struct {
	ID           string    `db:"id"`
	Name         string    `db:"name"`
	LogoURL      string    `db:"logo_url"`
	RedirectURIs []string  `db:"redirect_uris"`
	ClientSecret string    `db:"client_secret"`
	ZKRequired   bool      `db:"zk_required"`
	CreatedAt    time.Time `db:"created_at"`
}

type SSOChallenge struct {
	Nonce         string    `db:"nonce"`
	ClientID      string    `db:"client_id"`
	RedirectURI   string    `db:"redirect_uri"`
	State         string    `db:"state"`
	CodeChallenge string    `db:"code_challenge"`
	ExpiresAt     time.Time `db:"expires_at"`
	Used          bool      `db:"used"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Repository interfaces
// ─────────────────────────────────────────────────────────────────────────────

type WalletsQ interface {
	// Insert creates a new wallet row. Returns the created row.
	Insert(w Wallet) (Wallet, error)
	// GetByAddress returns the wallet with the given walletAddress, or nil.
	GetByAddress(walletAddress string) (*Wallet, error)
}

type AppCredentialsQ interface {
	// Insert creates a new app credential row.
	Insert(c AppCredential) (AppCredential, error)
	// RevokeByWallet marks all credentials for a wallet+platform as revoked.
	RevokeByWallet(walletID, platform string) error
	// GetActiveByWallet returns the current verified credential for a wallet+platform.
	GetActiveByWallet(walletID, platform string) (*AppCredential, error)
}

type AssertionsQ interface {
	// Insert creates a new assertion row.
	Insert(a Assertion) (Assertion, error)
	// GetByWalletAndType returns the latest assertion of the given type for a wallet.
	GetByWalletAndType(walletID, assertionType string) (*Assertion, error)
}

type PairwiseSubjectsQ interface {
	// Upsert inserts or returns the existing pairwise subject for wallet+client.
	Upsert(ps PairwiseSubject) (PairwiseSubject, error)
	// GetBySubject looks up a pairwise subject row by its subject string.
	GetBySubject(subject string) (*PairwiseSubject, error)
}

type SSOClientsQ interface {
	// GetByID returns the SSO client config, or nil if not found.
	GetByID(clientID string) (*SSOClient, error)
}

type SSOChallengesQ interface {
	// Insert stores a new challenge nonce.
	Insert(c SSOChallenge) error
	// Consume marks a challenge as used and returns it. Returns nil if not found, expired, or already used.
	Consume(nonce string) (*SSOChallenge, error)
	// DeleteExpired purges expired challenges (called from a background job or on demand).
	DeleteExpired() error
}

// WalletChallenge is a short-lived nonce issued for wallet registration (M2).
// Kept separate from SSOChallenge because registration has no client_id / PKCE.
type WalletChallenge struct {
	Nonce     string    `db:"nonce"`
	Platform  string    `db:"platform"`
	ExpiresAt time.Time `db:"expires_at"`
	Used      bool      `db:"used"`
}

type WalletChallengesQ interface {
	// Insert stores a new wallet registration challenge.
	Insert(c WalletChallenge) error
	// Consume atomically marks the nonce as used and returns it.
	// Returns nil (no error) when the nonce is not found, already used, or expired.
	Consume(nonce string) (*WalletChallenge, error)
}

// AuthCode is a one-time authorization code issued by /v1/authorize/verify
// and consumed by /v1/tokens/exchange (auth-code + PKCE flow, M3).
type AuthCode struct {
	Code            string    `db:"code"`
	ClientID        string    `db:"client_id"`
	PairwiseSubject string    `db:"pairwise_subject"`
	CodeChallenge   string    `db:"code_challenge"`
	ExpiresAt       time.Time `db:"expires_at"`
	Used            bool      `db:"used"`
	CreatedAt       time.Time `db:"created_at"`
}

type AuthCodesQ interface {
	// Insert stores a new auth code.
	Insert(c AuthCode) error
	// Consume atomically marks the code as used and returns it.
	// Returns nil (no error) when the code is not found, already used, or expired.
	Consume(code string) (*AuthCode, error)
}
