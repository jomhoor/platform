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
			handlers.CtxDeeplink(s.deeplink),
			handlers.CtxDB(s.db),
			handlers.CtxZKP(s.zkp),
		),
	)

	// Well-known files required for Universal Links (iOS) and App Links (Android).
	// These MUST be served before any auth routes because iOS/Android fetch them
	// on every app install without any credentials.
	r.Get("/.well-known/apple-app-site-association", handlers.AppleAppSiteAssociation)
	r.Get("/.well-known/assetlinks.json", handlers.AssetLinks)

	// Deep-link target for the SSO flow. iOS Universal Link interception is the
	// primary path (app opens before the browser makes a network request).
	// This handler is the fallback for browser-initiated navigations where iOS
	// does not intercept: it 302-redirects to the jomhoor:// custom scheme so
	// the wallet app still opens regardless.
	r.Get("/auth/sso", handlers.AuthSsoFallback)

	r.Route("/v1", func(r chi.Router) {
		// Wallet registration (M2)
		r.Post("/wallets/challenge", handlers.WalletChallenge)
		r.Post("/wallets/register", handlers.RegisterWallet)

		// Wallet recovery via ZK nullifier (M5). The wallet posts a fresh
		// query proof carrying the same nullifier_hash as the prior wallet;
		// sso-svc rebinds assertions + pairwise_subjects so the user keeps
		// the same `sub` at every relying party after reinstall.
		r.Post("/wallets/recover", handlers.RecoverWallet)

		// OAuth2 auth-code + PKCE flow (M3)
		r.Get("/authorize", handlers.Authorize)
		r.Post("/authorize/verify", handlers.Verify)
		r.Post("/tokens/exchange", handlers.Exchange)

		// Public client metadata for consent screen (M4)
		r.Get("/clients/{id}", handlers.GetClient)

		// ZK assertion submission (M5 item 4). Wallet posts a Rarimo query proof;
		// success inserts an `assertions` row that /v1/tokens/validate surfaces live.
		r.Post("/assertions/zk", handlers.SubmitZKAssertion)

		// Pre-flight ZK assertion check (M5 item 1). Wallet calls this before
		// the consent screen when an RP advertises `zk_required=true`, so the
		// user is routed through ZK escalation instead of hitting a silent 403
		// from /v1/authorize/verify.
		r.Get("/wallets/{address}/assertions/zk", handlers.GetZKAssertionStatus)

		// Token introspection (M3)
		r.With(middleware.AuthMiddleware(s.jwt, s.log, jwt.AccessTokenType)).
			Get("/tokens/validate", handlers.Validate)

		// Token refresh
		r.With(middleware.AuthMiddleware(s.jwt, s.log, jwt.RefreshTokenType)).
			Post("/tokens/refresh", handlers.Refresh)
	})

	return r
}
