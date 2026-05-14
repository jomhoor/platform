package pg

import (
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
)

const walletsTable = "wallets"

type walletsQ struct {
	db *sql.DB
}

func (d *DB) Wallets() data.WalletsQ {
	return &walletsQ{db: d.raw}
}

func (q *walletsQ) Insert(w data.Wallet) (data.Wallet, error) {
	query, args, err := sq.
		Insert(walletsTable).
		Columns("id", "wallet_address", "public_key_x", "public_key_y").
		Values(w.ID, w.WalletAddress, w.PublicKeyX, w.PublicKeyY).
		Suffix("RETURNING id, wallet_address, public_key_x, public_key_y, registered_at").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return data.Wallet{}, errors.Wrap(err, "build insert wallets sql")
	}

	row := q.db.QueryRow(query, args...)
	if err := row.Scan(&w.ID, &w.WalletAddress, &w.PublicKeyX, &w.PublicKeyY, &w.RegisteredAt); err != nil {
		return data.Wallet{}, errors.Wrap(err, "scan inserted wallet")
	}
	return w, nil
}

func (q *walletsQ) GetByAddress(walletAddress string) (*data.Wallet, error) {
	query, args, err := sq.
		Select("id", "wallet_address", "public_key_x", "public_key_y", "registered_at").
		From(walletsTable).
		Where(sq.Eq{"wallet_address": walletAddress}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build select wallet sql")
	}

	var w data.Wallet
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(&w.ID, &w.WalletAddress, &w.PublicKeyX, &w.PublicKeyY, &w.RegisteredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "scan wallet row")
	}
	return &w, nil
}
