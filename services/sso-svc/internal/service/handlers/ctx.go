package handlers

import (
	"context"
	"net/http"

	"github.com/jomhoor/sso-svc/internal/attestation"
	"github.com/jomhoor/sso-svc/internal/cookies"
	"github.com/jomhoor/sso-svc/internal/data/pg"
	"github.com/jomhoor/sso-svc/internal/deeplink"
	"github.com/jomhoor/sso-svc/internal/jwt"
	"github.com/jomhoor/sso-svc/internal/pairwise"
	"github.com/jomhoor/sso-svc/internal/zkp"
	"gitlab.com/distributed_lab/logan/v3"
)

type ctxKey int

const (
	logCtxKey ctxKey = iota
	jwtCtxKey
	claimCtxKey
	pairwiseCtxKey
	attestationCtxKey
	cookiesCtxKey
	deeplinkCtxKey
	dbCtxKey
	zkpCtxKey
)

// ── Setters ───────────────────────────────────────────────────────────────────

func CtxLog(entry *logan.Entry) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, logCtxKey, entry)
	}
}

func CtxJWT(issuer *jwt.JWTIssuer) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, jwtCtxKey, issuer)
	}
}

func CtxClaim(claim *jwt.AuthClaim) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, claimCtxKey, claim)
	}
}

func CtxPairwise(d *pairwise.Deriver) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, pairwiseCtxKey, d)
	}
}

func CtxAttestation(cfg *attestation.Config) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, attestationCtxKey, cfg)
	}
}

func CtxCookies(c *cookies.Cookies) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, cookiesCtxKey, c)
	}
}

func CtxDeeplink(d *deeplink.Config) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, deeplinkCtxKey, d)
	}
}

func CtxDB(db *pg.DB) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, dbCtxKey, db)
	}
}

func CtxZKP(v *zkp.Verifier) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, zkpCtxKey, v)
	}
}

// ── Getters ───────────────────────────────────────────────────────────────────

func Log(r *http.Request) *logan.Entry {
	return r.Context().Value(logCtxKey).(*logan.Entry)
}

func JWT(r *http.Request) *jwt.JWTIssuer {
	return r.Context().Value(jwtCtxKey).(*jwt.JWTIssuer)
}

func Claim(r *http.Request) *jwt.AuthClaim {
	return r.Context().Value(claimCtxKey).(*jwt.AuthClaim)
}

func Pairwise(r *http.Request) *pairwise.Deriver {
	return r.Context().Value(pairwiseCtxKey).(*pairwise.Deriver)
}

func Attestation(r *http.Request) *attestation.Config {
	return r.Context().Value(attestationCtxKey).(*attestation.Config)
}

func Cookies(r *http.Request) *cookies.Cookies {
	return r.Context().Value(cookiesCtxKey).(*cookies.Cookies)
}

func Deeplink(r *http.Request) *deeplink.Config {
	return r.Context().Value(deeplinkCtxKey).(*deeplink.Config)
}

func DB(r *http.Request) *pg.DB {
	return r.Context().Value(dbCtxKey).(*pg.DB)
}

func ZKP(r *http.Request) *zkp.Verifier {
	return r.Context().Value(zkpCtxKey).(*zkp.Verifier)
}
