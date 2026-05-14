package pg

import (
	"database/sql"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
)

const challengesTable = "sso_challenges"

type challengesQ struct {
	db *sql.DB
}

func (d *DB) Challenges() data.SSOChallengesQ {
	return &challengesQ{db: d.raw}
}

func (q *challengesQ) Insert(c data.SSOChallenge) error {
	query, args, err := sq.
		Insert(challengesTable).
		Columns("nonce", "client_id", "redirect_uri", "state", "code_challenge", "expires_at").
		Values(c.Nonce, c.ClientID, c.RedirectURI, c.State, c.CodeChallenge, c.ExpiresAt).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return errors.Wrap(err, "build insert challenge sql")
	}

	_, err = q.db.Exec(query, args...)
	return errors.Wrap(err, "exec insert challenge")
}

// Consume atomically marks the challenge as used and returns it.
// Returns nil (no error) when the nonce is not found, already used, or expired.
func (q *challengesQ) Consume(nonce string) (*data.SSOChallenge, error) {
	query, args, err := sq.
		Update(challengesTable).
		Set("used", true).
		Where(sq.And{
			sq.Eq{"nonce": nonce},
			sq.Eq{"used": false},
			sq.Gt{"expires_at": time.Now().UTC()},
		}).
		Suffix("RETURNING nonce, client_id, redirect_uri, state, code_challenge, expires_at, used").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build consume challenge sql")
	}

	var c data.SSOChallenge
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(&c.Nonce, &c.ClientID, &c.RedirectURI, &c.State, &c.CodeChallenge, &c.ExpiresAt, &c.Used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "scan consumed challenge")
	}
	return &c, nil
}

func (q *challengesQ) DeleteExpired() error {
	query, args, err := sq.
		Delete(challengesTable).
		Where(sq.Lt{"expires_at": time.Now().UTC()}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return errors.Wrap(err, "build delete expired challenges sql")
	}

	_, err = q.db.Exec(query, args...)
	return errors.Wrap(err, "exec delete expired challenges")
}
