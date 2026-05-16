package handlers

import (
	"net/http"
)

// AuthSsoFallback handles GET /auth/sso when iOS Universal Link interception
// fails (e.g. browser-initiated redirect rather than a user tap).
//
// The primary path is: iOS intercepts https://sso.jomhoor.org/auth/sso?... before
// the browser makes a network request, opening the Jomhoor wallet app directly.
//
// The fallback path (this handler) is: the browser fetches the URL normally and
// we respond with a redirect to the jomhoor:// custom scheme, which iOS will open
// in the wallet app regardless of Universal Link interception state.
func AuthSsoFallback(w http.ResponseWriter, r *http.Request) {
	cfg := Deeplink(r)

	target := cfg.CustomScheme
	if qs := r.URL.RawQuery; qs != "" {
		target += "?" + qs
	}

	http.Redirect(w, r, target, http.StatusFound)
}
