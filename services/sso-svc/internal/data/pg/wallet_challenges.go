package pg

import (
	"database/sql"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
)

const walletChallengesTable = "wallet_challenges"

type walletChallengesQ struct {
	db *sql.DB
}

func (d *DB) WalletChallenges() data.WalletChallengesQ {
	return &walletChallengesQ{db: d.raw}
}

func (q *walletChallengesQ) Insert(c data.WalletChallenge) error {
	query, args, err := sq.
		Insert(walletChallengesTable).
		Columns("nonce", "platform", "expires_at").
		Values(c.Nonce, c.Platform, c.ExpiresAt).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return errors.Wrap(err, "build insert wallet_challenge sql")
	}

	_, err = q.db.Exec(query, args...)
	return errors.Wrap(err, "exec insert wallet_challenge")
}

// Consume atomically marks the challenge as used and returns it.
// Returns nil (no error) when the nonce is not found, already used, or expired.
func (q *walletChallengesQ) Consume(nonce string) (*data.WalletChallenge, error) {
	query, args, err := sq.
		Update(walletChallengesTable).
		Set("used", true).
		Where(sq.And{
			sq.Eq{"nonce": nonce},
			sq.Eq{"used": false},
			sq.Gt{"expires_at": time.Now().UTC()},
		}).
		Suffix("RETURNING nonce, platform, expires_at, used").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build consume wallet_challenge sql")
	}

	var c data.WalletChallenge
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(&c.Nonce, &c.Platform, &c.ExpiresAt, &c.Used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "scan consumed wallet_challenge")
	}
	return &c, nil
}
