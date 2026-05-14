package pg

import (
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/lib/pq"
	"github.com/pkg/errors"
)

const clientsTable = "sso_clients"

type clientsQ struct {
	db *sql.DB
}

func (d *DB) Clients() data.SSOClientsQ {
	return &clientsQ{db: d.raw}
}

func (q *clientsQ) GetByID(clientID string) (*data.SSOClient, error) {
	query, args, err := sq.
		Select("id", "name", "logo_url", "redirect_uris", "client_secret", "zk_required", "created_at").
		From(clientsTable).
		Where(sq.Eq{"id": clientID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build select client sql")
	}

	var c data.SSOClient
	var redirectURIs pq.StringArray
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(&c.ID, &c.Name, &c.LogoURL, &redirectURIs, &c.ClientSecret, &c.ZKRequired, &c.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "scan client row")
	}
	c.RedirectURIs = []string(redirectURIs)
	return &c, nil
}
