package pg

import (
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
)

const pairwiseTable = "pairwise_subjects"

type pairwiseQ struct {
	db *sql.DB
}

func (d *DB) PairwiseSubjects() data.PairwiseSubjectsQ {
	return &pairwiseQ{db: d.raw}
}

// Upsert inserts a new pairwise subject. If the (wallet_id, client_id) pair already
// exists, it does nothing and returns the existing row.
func (q *pairwiseQ) Upsert(ps data.PairwiseSubject) (data.PairwiseSubject, error) {
	insertSQL, args, err := sq.
		Insert(pairwiseTable).
		Columns("id", "wallet_id", "client_id", "subject").
		Values(ps.ID, ps.WalletID, ps.ClientID, ps.Subject).
		Suffix("ON CONFLICT (wallet_id, client_id) DO NOTHING").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return data.PairwiseSubject{}, errors.Wrap(err, "build upsert pairwise sql")
	}

	if _, err = q.db.Exec(insertSQL, args...); err != nil {
		return data.PairwiseSubject{}, errors.Wrap(err, "exec upsert pairwise")
	}

	// Always SELECT to get the canonical row (either just-inserted or pre-existing).
	return q.GetByWalletAndClient(ps.WalletID, ps.ClientID)
}

func (q *pairwiseQ) GetBySubject(subject string) (*data.PairwiseSubject, error) {
	query, args, err := sq.
		Select("id", "wallet_id", "client_id", "subject", "created_at").
		From(pairwiseTable).
		Where(sq.Eq{"subject": subject}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build select pairwise by subject sql")
	}

	var ps data.PairwiseSubject
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(&ps.ID, &ps.WalletID, &ps.ClientID, &ps.Subject, &ps.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "scan pairwise subject row")
	}
	return &ps, nil
}

func (q *pairwiseQ) GetByWalletAndClient(walletID, clientID string) (data.PairwiseSubject, error) {
	query, args, err := sq.
		Select("id", "wallet_id", "client_id", "subject", "created_at").
		From(pairwiseTable).
		Where(sq.And{
			sq.Eq{"wallet_id": walletID},
			sq.Eq{"client_id": clientID},
		}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return data.PairwiseSubject{}, errors.Wrap(err, "build select pairwise by wallet+client sql")
	}

	var ps data.PairwiseSubject
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(&ps.ID, &ps.WalletID, &ps.ClientID, &ps.Subject, &ps.CreatedAt); err != nil {
		return data.PairwiseSubject{}, errors.Wrap(err, "scan pairwise subject row by wallet+client")
	}
	return ps, nil
}
