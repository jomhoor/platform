package pg

import (
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
)

const assertionsTable = "assertions"

type assertionsQ struct {
	db *sql.DB
}

func (d *DB) Assertions() data.AssertionsQ {
	return &assertionsQ{db: d.raw}
}

// GetByWalletAndType returns the most recent active assertion of the given type
// for the wallet, or nil if none exists. Expired or status=false rows are
// treated as missing — callers should not need to re-check.
func (q *assertionsQ) GetByWalletAndType(walletID, assertionType string) (*data.Assertion, error) {
	query, args, err := sq.
		Select("id", "wallet_id", "assertion_type", "status", "nullifier_hash", "source", "issued_at", "expires_at").
		From(assertionsTable).
		Where(sq.And{
			sq.Eq{"wallet_id": walletID},
			sq.Eq{"assertion_type": assertionType},
			sq.Eq{"status": true},
			sq.Or{
				sq.Eq{"expires_at": nil},
				sq.Expr("expires_at > NOW()"),
			},
		}).
		OrderBy("issued_at DESC").
		Limit(1).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build select assertion sql")
	}

	var a data.Assertion
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(
		&a.ID, &a.WalletID, &a.AssertionType, &a.Status,
		&a.NullifierHash, &a.Source, &a.IssuedAt, &a.ExpiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "scan assertion row")
	}
	return &a, nil
}
