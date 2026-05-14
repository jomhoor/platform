package service

import (
	"github.com/go-chi/chi"
	"github.com/jomhoor/sso-svc/internal/jwt"
	"github.com/jomhoor/sso-svc/internal/service/handlers"
	"github.com/jomhoor/sso-svc/internal/service/middleware"
	"gitlab.com/distributed_lab/ape"
)

func (s *service) router() chi.Router {
	r := chi.NewRouter()

	r.Use(
		ape.RecoverMiddleware(s.log),
		ape.LoganMiddleware(s.log),
		ape.CtxMiddleware(
			handlers.CtxLog(s.log),
			handlers.CtxJWT(s.jwt),
			handlers.CtxPairwise(s.pairwise),
			handlers.CtxAttestation(s.attestation),
			handlers.CtxCookies(s.cookies),
			handlers.CtxDB(s.db),
		),
	)

	// Well-known files required for Universal Links (iOS) and App Links (Android).
	// These MUST be served before any auth routes because iOS/Android fetch them
	// on every app install without any credentials.
	r.Get("/.well-known/apple-app-site-association", handlers.AppleAppSiteAssociation)
	r.Get("/.well-known/assetlinks.json", handlers.AssetLinks)

	r.Route("/v1", func(r chi.Router) {
		// Wallet registration (M2)
		r.Post("/wallets/challenge", handlers.WalletChallenge)
		r.Post("/wallets/register", handlers.RegisterWallet)

		// OAuth2 auth-code + PKCE flow (M3)
		r.Get("/authorize", handlers.Authorize)
		r.Post("/authorize/verify", handlers.Verify)
		r.Post("/tokens/exchange", handlers.Exchange)

		// Token introspection (M3)
		r.With(middleware.AuthMiddleware(s.jwt, s.log, jwt.AccessTokenType)).
			Get("/tokens/validate", handlers.Validate)

		// Token refresh
		r.With(middleware.AuthMiddleware(s.jwt, s.log, jwt.RefreshTokenType)).
			Post("/tokens/refresh", handlers.Refresh)
	})

	return r
}
