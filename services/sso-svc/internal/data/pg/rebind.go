package pg

import (
	"github.com/pkg/errors"
)

// RebindWallet atomically migrates all assertions and pairwise_subjects from
// oldWalletID to newWalletID. This is the database-side half of the M5
// ZK-nullifier recovery flow (POST /v1/wallets/recover).
//
// Semantics:
//
//   - assertions: every row whose wallet_id = oldWalletID is rewritten to
//     newWalletID. The history (including expired rows) follows the
//     nullifier to its new wallet so /v1/tokens/validate continues to surface
//     the same trust history.
//
//   - pairwise_subjects: the goal is RP-level continuity — every relying
//     party that already saw the old wallet must continue to see the same
//     `sub` after recovery. If the new wallet has already minted a pairwise
//     subject for some client (e.g. the user logged into a new RP with the
//     new wallet before recovering), the new row is deleted and the old row
//     is rebound so the older subject wins. The (wallet_id, client_id)
//     uniqueness constraint forbids both rows coexisting.
//
// Both updates run inside a single transaction. Caller invokes this once per
// recovery; idempotent when oldWalletID == newWalletID (no-op).
func (d *DB) RebindWallet(oldWalletID, newWalletID string) error {
	if oldWalletID == "" || newWalletID == "" {
		return errors.New("oldWalletID and newWalletID required")
	}
	if oldWalletID == newWalletID {
		return nil
	}

	tx, err := d.raw.Begin()
	if err != nil {
		return errors.Wrap(err, "begin rebind tx")
	}
	defer func() {
		// Rollback is a no-op if Commit already succeeded.
		_ = tx.Rollback()
	}()

	// 1. Delete new-wallet pairwise rows that would collide with old-wallet
	//    rows on the unique (wallet_id, client_id) constraint. The old row
	//    wins because it represents the durable identity the RP already knows.
	if _, err := tx.Exec(`
		DELETE FROM pairwise_subjects
		WHERE wallet_id = $1
		  AND client_id IN (
		      SELECT client_id FROM pairwise_subjects WHERE wallet_id = $2
		  )
	`, newWalletID, oldWalletID); err != nil {
		return errors.Wrap(err, "delete colliding new-wallet pairwise rows")
	}

	// 2. Rebind remaining pairwise_subjects from old → new.
	if _, err := tx.Exec(
		`UPDATE pairwise_subjects SET wallet_id = $1 WHERE wallet_id = $2`,
		newWalletID, oldWalletID,
	); err != nil {
		return errors.Wrap(err, "rebind pairwise_subjects")
	}

	// 3. Rebind assertions from old → new. No uniqueness conflict possible.
	if _, err := tx.Exec(
		`UPDATE assertions SET wallet_id = $1 WHERE wallet_id = $2`,
		newWalletID, oldWalletID,
	); err != nil {
		return errors.Wrap(err, "rebind assertions")
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "commit rebind tx")
	}
	return nil
}
