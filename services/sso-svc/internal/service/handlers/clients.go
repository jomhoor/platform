// M4: Public client metadata endpoint.
//
// The wallet app calls GET /v1/clients/{id} during the consent step to render
// the requesting app's display name and logo instead of a raw client_id.
//
// SECURITY: client_secret is NEVER returned — this endpoint is unauthenticated
// and any value here is effectively public. Only fields safe for an end-user
// consent screen are exposed.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

// clientMetadataResponse is the public projection of an SSOClient row.
// Intentionally narrow: no client_secret, no internal IDs beyond the client_id
// the caller already knows.
type clientMetadataResponse struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	LogoURL      *string `json:"logo_url,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	ZKRequired   bool    `json:"zk_required"`
}

// GetClient handles GET /v1/clients/{id}.
//
// Returns 404 for unknown clients. Unauthenticated by design — the consent
// screen needs to render this before any tokens exist.
func GetClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "id")
	if clientID == "" {
		ape.RenderErr(w, problems.BadRequest(errors.New("client id required"))...)
		return
	}

	client, err := DB(r).Clients().GetByID(clientID)
	if err != nil {
		Log(r).WithError(err).Error("lookup sso client")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if client == nil {
		ape.RenderErr(w, problems.NotFound())
		return
	}

	resp := clientMetadataResponse{
		ID:           client.ID,
		Name:         client.Name,
		LogoURL:      client.LogoURL,
		RedirectURIs: client.RedirectURIs,
		ZKRequired:   client.ZKRequired,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		Log(r).WithError(err).Error("encode client metadata response")
	}
}
