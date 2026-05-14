package pg

import (
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/jomhoor/sso-svc/internal/data"
	"github.com/pkg/errors"
)

const credentialsTable = "app_credentials"

type credentialsQ struct {
	db *sql.DB
}

func (d *DB) AppCredentials() data.AppCredentialsQ {
	return &credentialsQ{db: d.raw}
}

func (q *credentialsQ) Insert(c data.AppCredential) (data.AppCredential, error) {
	query, args, err := sq.
		Insert(credentialsTable).
		Columns("id", "wallet_id", "platform", "credential_id", "attestation_key_id", "attestation_status").
		Values(c.ID, c.WalletID, c.Platform, c.CredentialID, c.AttestationKeyID, c.AttestationStatus).
		Suffix("RETURNING id, wallet_id, platform, credential_id, attestation_key_id, attestation_status, attested_at, last_verified_at").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return data.AppCredential{}, errors.Wrap(err, "build insert credential sql")
	}

	row := q.db.QueryRow(query, args...)
	if err := row.Scan(
		&c.ID, &c.WalletID, &c.Platform, &c.CredentialID,
		&c.AttestationKeyID, &c.AttestationStatus, &c.AttestedAt, &c.LastVerifiedAt,
	); err != nil {
		return data.AppCredential{}, errors.Wrap(err, "scan inserted credential")
	}
	return c, nil
}

func (q *credentialsQ) RevokeByWallet(walletID, platform string) error {
	query, args, err := sq.
		Update(credentialsTable).
		Set("attestation_status", "revoked").
		Where(sq.And{
			sq.Eq{"wallet_id": walletID},
			sq.Eq{"platform": platform},
			sq.NotEq{"attestation_status": "revoked"},
		}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return errors.Wrap(err, "build revoke credential sql")
	}

	_, err = q.db.Exec(query, args...)
	return errors.Wrap(err, "exec revoke credentials")
}

func (q *credentialsQ) GetActiveByWallet(walletID, platform string) (*data.AppCredential, error) {
	query, args, err := sq.
		Select("id", "wallet_id", "platform", "credential_id", "attestation_key_id", "attestation_status", "attested_at", "last_verified_at").
		From(credentialsTable).
		Where(sq.And{
			sq.Eq{"wallet_id": walletID},
			sq.Eq{"platform": platform},
			sq.Eq{"attestation_status": "verified"},
		}).
		OrderBy("attested_at DESC").
		Limit(1).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, errors.Wrap(err, "build select active credential sql")
	}

	var c data.AppCredential
	row := q.db.QueryRow(query, args...)
	if err := row.Scan(
		&c.ID, &c.WalletID, &c.Platform, &c.CredentialID,
		&c.AttestationKeyID, &c.AttestationStatus, &c.AttestedAt, &c.LastVerifiedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "scan active credential")
	}
	return &c, nil
}
