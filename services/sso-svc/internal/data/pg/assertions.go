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

// Insert writes a new assertion row and returns the persisted record (including
// the DB-generated id and issued_at). The caller should leave a.ID empty so
// Postgres DEFAULT gen_random_uuid() assigns it.
func (q *assertionsQ) Insert(a data.Assertion) (data.Assertion, error) {
	cols := []string{"wallet_id", "assertion_type", "status", "nullifier_hash", "source"}
	vals := []interface{}{a.WalletID, a.AssertionType, a.Status, a.NullifierHash, a.Source}

	if a.ExpiresAt != nil {
		cols = append(cols, "expires_at")
		vals = append(vals, a.ExpiresAt)
	}

	query, args, err := sq.
		Insert(assertionsTable).
		Columns(cols...).
		Values(vals...).
		Suffix("RETURNING id, wallet_id, assertion_type, status, nullifier_hash, source, issued_at, expires_at").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return data.Assertion{}, errors.Wrap(err, "build insert assertion sql")
	}

	var out data.Assertion
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(
		&out.ID, &out.WalletID, &out.AssertionType, &out.Status,
		&out.NullifierHash, &out.Source, &out.IssuedAt, &out.ExpiresAt,
	); err != nil {
		return data.Assertion{}, errors.Wrap(err, "scan inserted assertion")
	}
	return out, nil
}

// GetLatestByNullifier returns the most recent assertion carrying the given
// nullifier_hash, regardless of status or expiry. Recovery uses this to map a
// re-proven nullifier back to its prior wallet_id; expired or revoked rows
// still count as evidence that the nullifier was once bound to a wallet.
func (q *assertionsQ) GetLatestByNullifier(nullifierHash []byte) (*data.Assertion, error) {
	if len(nullifierHash) == 0 {
		return nil, nil
	}
	query, args, err := sq.
		Select("id", "wallet_id", "assertion_type", "status", "nullifier_hash", "source", "issued_at", "expires_at").
		From(assertionsTable).
		Where(sq.Eq{"nullifier_hash": nullifierHash}).
		OrderBy("issued_at DESC").
		Limit(1).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build select assertion by nullifier sql")
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
		return nil, errors.Wrap(err, "scan assertion by nullifier")
	}
	return &a, nil
}
