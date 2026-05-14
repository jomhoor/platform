package middleware

import (
	"net/http"
	"strings"

	"github.com/jomhoor/sso-svc/internal/jwt"
	"github.com/jomhoor/sso-svc/internal/service/handlers"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3"
)

func AuthMiddleware(issuer *jwt.JWTIssuer, log *logan.Entry, expectedType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get(jwt.AuthorizationHeaderName)
			if !strings.HasPrefix(header, jwt.BearerTokenPrefix) {
				ape.RenderErr(w, problems.Unauthorized())
				return
			}

			tokenStr := strings.TrimPrefix(header, jwt.BearerTokenPrefix)
			claim, err := issuer.ValidateJWT(tokenStr)
			if err != nil {
				log.WithError(err).Debug("jwt validation failed")
				ape.RenderErr(w, problems.Unauthorized())
				return
			}

			if claim.Type != expectedType {
				ape.RenderErr(w, problems.Unauthorized())
				return
			}

			next.ServeHTTP(w, r.WithContext(
				handlers.CtxClaim(claim)(r.Context()),
			))
		})
	}
}
