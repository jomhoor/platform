package pg

import (
	"database/sql"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
)

const authCodesTable = "sso_auth_codes"

type authCodesQ struct {
	db *sql.DB
}

func (d *DB) AuthCodes() data.AuthCodesQ {
	return &authCodesQ{db: d.raw}
}

func (q *authCodesQ) Insert(c data.AuthCode) error {
	query, args, err := sq.
		Insert(authCodesTable).
		Columns("code", "client_id", "pairwise_subject", "code_challenge", "zk_verified", "expires_at").
		Values(c.Code, c.ClientID, c.PairwiseSubject, c.CodeChallenge, c.ZKVerified, c.ExpiresAt).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return errors.Wrap(err, "build insert auth code sql")
	}

	if _, err := q.db.Exec(query, args...); err != nil {
		return errors.Wrap(err, "exec insert auth code")
	}
	return nil
}

// Consume atomically marks the code as used and returns it.
// Returns nil (no error) when the code is not found, already used, or expired.
func (q *authCodesQ) Consume(code string) (*data.AuthCode, error) {
	query, args, err := sq.
		Update(authCodesTable).
		Set("used", true).
		Where(sq.And{
			sq.Eq{"code": code},
			sq.Eq{"used": false},
			sq.Gt{"expires_at": time.Now().UTC()},
		}).
		Suffix("RETURNING code, client_id, pairwise_subject, code_challenge, zk_verified, expires_at, used, created_at").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build consume auth code sql")
	}

	var c data.AuthCode
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(
		&c.Code, &c.ClientID, &c.PairwiseSubject, &c.CodeChallenge,
		&c.ZKVerified, &c.ExpiresAt, &c.Used, &c.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "scan consumed auth code")
	}
	return &c, nil
}
