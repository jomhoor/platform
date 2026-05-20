package static

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed fonts
var files embed.FS

// Handler returns an http.Handler that serves the embedded static files
// under the given URL prefix (e.g. "/static/").
// Strip the prefix before calling this so the FS root lines up correctly.
func Handler(prefix string) http.Handler {
	sub, err := fs.Sub(files, ".")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix(prefix, http.FileServer(http.FS(sub)))
}
