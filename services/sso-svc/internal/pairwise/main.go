package pairwise

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

// Deriver computes client-specific pseudonymous subjects from wallet identifiers.
// Same wallet + same client → same subject. Different clients → different subjects.
// This prevents cross-site user correlation.
type Deriver struct {
	secret []byte
}

// Derive computes HMAC-SHA256(secret, walletID || ":" || clientID) and returns
// the result as a hex string prefixed with "ps_" (pairwise subject).
// walletID should be the internal UUID string from the wallets table.
func (d *Deriver) Derive(walletID, clientID string) string {
	mac := hmac.New(sha256.New, d.secret)
	fmt.Fprintf(mac, "%s:%s", walletID, clientID)
	return "ps_" + hex.EncodeToString(mac.Sum(nil))
}

// DeriveFromNullifier computes the ZK-tier pairwise subject anchored on the
// nullifier hash rather than the wallet ID. This ensures pairwiseSubject is
// stable across re-installs for ZK-verified users (Phase 2).
// nullifierHex should be the hex-encoded nullifier hash from the assertion row.
func (d *Deriver) DeriveFromNullifier(nullifierHex, clientID string) string {
	mac := hmac.New(sha256.New, d.secret)
	fmt.Fprintf(mac, "zk:%s:%s", nullifierHex, clientID)
	return "ps_" + hex.EncodeToString(mac.Sum(nil))
}

// ─────────────────────────────────────────────────────────────────────────────
// Config wiring
// ─────────────────────────────────────────────────────────────────────────────

type Pairwiser interface {
	Pairwise() *Deriver
}

type pairwiser struct {
	once   comfig.Once
	getter kv.Getter
}

func NewPairwiser(getter kv.Getter) Pairwiser {
	return &pairwiser{getter: getter}
}

type pairwiseConfig struct {
	SecretKey string `fig:"secret_key,required"`
}

func (p *pairwiser) Pairwise() *Deriver {
	return p.once.Do(func() interface{} {
		cfg := pairwiseConfig{}
		if err := figure.Out(&cfg).From(kv.MustGetStringMap(p.getter, "pairwise")).Please(); err != nil {
			panic(errors.WithMessage(err, "failed to figure out pairwise config"))
		}

		key, err := hex.DecodeString(cfg.SecretKey)
		if err != nil {
			// Accept raw strings too (for local dev convenience)
			key = []byte(cfg.SecretKey)
		}
		if len(key) < 32 {
			panic("pairwise.secret_key must be at least 32 bytes")
		}

		return &Deriver{secret: key}
	}).(*Deriver)
}
