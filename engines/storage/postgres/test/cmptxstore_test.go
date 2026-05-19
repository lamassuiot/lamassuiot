package postgrestest

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupCMPTxRepo(t *testing.T) (storage.CMPTransactionRepo, func()) {
	t.Helper()
	cfg, suite := BeforeSuite([]string{postgres.DMS_DB_NAME}, false)
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "CMP-TX-Test")

	err := postgres.MigrateDatabase(logger, cfg, postgres.DMS_DB_NAME)
	require.NoError(t, err)

	repo, err := postgres.NewCMPTransactionRepository(logger, suite.DB[postgres.DMS_DB_NAME])
	require.NoError(t, err)

	return repo, suite.AfterSuite
}

func newTx(txID, dmsID string, ttl time.Duration) storage.CMPTransaction {
	return storage.CMPTransaction{
		TransactionID: txID,
		DMSID:         dmsID,
		CertDER:       []byte("fake-cert-der"),
		SentNonce:     []byte("fake-nonce-16byt"),
		State:         storage.CMPTransactionStateIssued,
		ExpiresAt:     time.Now().Add(ttl),
		CreatedAt:     time.Now(),
	}
}

// newPendingTx builds a PENDING transaction used to seed the async-issuance
// worker path: cert is not yet issued, the row carries the CSR DER the worker
// will hand to LWCEnroll/LWCReenroll once it picks the row up.
func newPendingTx(txID, dmsID string, ttl time.Duration) storage.CMPTransaction {
	return storage.CMPTransaction{
		TransactionID:  txID,
		DMSID:          dmsID,
		CertDER:        nil,
		SentNonce:      []byte("fake-nonce-16byt"),
		State:          storage.CMPTransactionStatePending,
		CSRDER:         []byte("fake-csr-der"),
		IsReenrollment: false,
		ExpiresAt:      time.Now().Add(ttl),
		CreatedAt:      time.Now(),
	}
}

// TestCMPTx_InsertAndSelectAndDelete is the happy path: insert, then fetch+delete.
func TestCMPTx_InsertAndSelectAndDelete(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-1"))

	tx := newTx(txID, "dms-a", 5*time.Minute)
	require.NoError(t, repo.Insert(ctx, tx))

	got, ok, err := repo.SelectAndDelete(ctx, txID)
	require.NoError(t, err)
	assert.True(t, ok, "should find the transaction")
	assert.Equal(t, txID, got.TransactionID)
	assert.Equal(t, "dms-a", got.DMSID)
	assert.Equal(t, tx.CertDER, got.CertDER)
	assert.Equal(t, tx.SentNonce, got.SentNonce)
}

// TestCMPTx_SelectAndDeleteIsDestructive verifies a second lookup returns nothing.
func TestCMPTx_SelectAndDeleteIsDestructive(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-destr"))

	require.NoError(t, repo.Insert(ctx, newTx(txID, "dms-b", 5*time.Minute)))
	_, ok, err := repo.SelectAndDelete(ctx, txID)
	require.NoError(t, err)
	require.True(t, ok)

	// second call: should be gone
	_, ok, err = repo.SelectAndDelete(ctx, txID)
	require.NoError(t, err)
	assert.False(t, ok, "row should have been deleted by the first call")
}

// TestCMPTx_DuplicateInsertReturnsError covers the replay-attack guard.
func TestCMPTx_DuplicateInsertReturnsError(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-dup"))

	require.NoError(t, repo.Insert(ctx, newTx(txID, "dms-c", 5*time.Minute)))

	err := repo.Insert(ctx, newTx(txID, "dms-c", 5*time.Minute))
	assert.ErrorIs(t, err, errs.ErrCMPTransactionAlreadyExists)
}

// TestCMPTx_ExpiredTransactionNotFound ensures expired rows are invisible.
func TestCMPTx_ExpiredTransactionNotFound(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-expired"))

	// Insert with a TTL in the past so it is already expired.
	tx := newTx(txID, "dms-d", -1*time.Second)
	require.NoError(t, repo.Insert(ctx, tx))

	_, ok, err := repo.SelectAndDelete(ctx, txID)
	require.NoError(t, err)
	assert.False(t, ok, "expired transaction should not be returned")
}

// TestCMPTx_SelectUnknownReturnsFalse covers an unknown transactionID.
func TestCMPTx_SelectUnknownReturnsFalse(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	_, ok, err := repo.SelectAndDelete(context.Background(), "nonexistent-tx-id")
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestCMPTx_LifecycleRetryAfterCertConf models a real CMP flow:
//
//  1. EE sends ir → server stores a pending transaction with this txID.
//  2. EE retries the same ir (lost response, network glitch). While the
//     pending transaction is still live the retry MUST be rejected so the
//     server never issues a second certificate for the same exchange
//     (RFC 4210 §3.1 transactionIdInUse).
//  3. EE sends certConf for the original transaction → server consumes the
//     row via SelectAndDelete.
//  4. EE later starts a brand-new exchange that happens to reuse the same
//     transactionID. The row is gone, so Insert MUST succeed.
func TestCMPTx_LifecycleRetryAfterCertConf(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-life-confirm"))

	// 1) initial IR — succeeds.
	require.NoError(t, repo.Insert(ctx, newTx(txID, "dms-life-c", 5*time.Minute)))

	exists, err := repo.Exists(ctx, txID)
	require.NoError(t, err)
	assert.True(t, exists, "pending tx must be visible to Exists immediately after Insert")

	// 2) replay during the pending window — rejected.
	err = repo.Insert(ctx, newTx(txID, "dms-life-c", 5*time.Minute))
	require.ErrorIs(t, err, errs.ErrCMPTransactionAlreadyExists,
		"replay while the original tx is still pending must be rejected")

	// 3) certConf consumes the pending transaction.
	_, ok, err := repo.SelectAndDelete(ctx, txID)
	require.NoError(t, err)
	require.True(t, ok, "SelectAndDelete must return the pending row")

	exists, err = repo.Exists(ctx, txID)
	require.NoError(t, err)
	assert.False(t, exists, "after certConf the tx must be gone from Exists")

	// 4) same txID is reusable for a fresh exchange.
	require.NoError(t, repo.Insert(ctx, newTx(txID, "dms-life-c", 5*time.Minute)),
		"after certConf consumed the row the same txID must be reusable")
}

// TestCMPTx_LifecycleRetryAfterExpiryAndCleanup documents that an expired
// pending transaction is only reclaimed by DeleteExpired:
//
//  1. EE sends ir → row inserted with a short TTL.
//  2. EE retries while the row is still live → rejected (duplicate).
//  3. TTL elapses. The row is invisible to Exists and SelectAndDelete (both
//     filter by expires_at > now()), so the controller's early duplicate
//     check correctly stops blocking. However the primary key still occupies
//     the table, so Insert continues to report ErrCMPTransactionAlreadyExists.
//     This is the documented controller-side behavior: stale tx IDs must be
//     garbage-collected before they can be reused.
//  4. DeleteExpired purges the expired row.
//  5. The EE retries → Insert now succeeds.
func TestCMPTx_LifecycleRetryAfterExpiryAndCleanup(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-life-expiry"))
	const ttl = 50 * time.Millisecond

	// 1) initial IR with a deliberately short TTL so the test does not have
	// to wait minutes for the row to expire.
	require.NoError(t, repo.Insert(ctx, newTx(txID, "dms-life-e", ttl)))

	// 2) replay during the live window.
	err := repo.Insert(ctx, newTx(txID, "dms-life-e", ttl))
	require.ErrorIs(t, err, errs.ErrCMPTransactionAlreadyExists,
		"replay while the original tx is still live must be rejected")

	// 3) wait for the TTL to elapse.
	time.Sleep(ttl + 50*time.Millisecond)

	// Expired rows are invisible to read operations…
	exists, err := repo.Exists(ctx, txID)
	require.NoError(t, err)
	assert.False(t, exists, "expired row must be invisible to Exists")

	_, ok, err := repo.SelectAndDelete(ctx, txID)
	require.NoError(t, err)
	assert.False(t, ok, "expired row must be invisible to SelectAndDelete")

	// …but the PK still blocks a fresh Insert with the same txID until the
	// janitor runs. This is what makes DeleteExpired load-bearing.
	err = repo.Insert(ctx, newTx(txID, "dms-life-e", 5*time.Minute))
	require.ErrorIs(t, err, errs.ErrCMPTransactionAlreadyExists,
		"expired-but-not-purged row must still block re-insertion of the same PK")

	// 4) janitor reclaims the slot.
	require.NoError(t, repo.DeleteExpired(ctx))

	// 5) retry now succeeds.
	require.NoError(t, repo.Insert(ctx, newTx(txID, "dms-life-e", 5*time.Minute)),
		"after DeleteExpired the txID must be reusable")
}

// ---------------------------------------------------------------------------
// Async issuance (RFC 9483 §4.4) state-machine tests
// ---------------------------------------------------------------------------

// TestCMPTx_InsertPendingHasNoCert verifies that a PENDING row is accepted
// even when CertDER is empty (cert hasn't been issued yet) and Select returns
// it with the correct state.
func TestCMPTx_InsertPendingHasNoCert(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-pend-1"))

	require.NoError(t, repo.Insert(ctx, newPendingTx(txID, "dms-async", 5*time.Minute)))

	got, ok, err := repo.Select(ctx, txID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, storage.CMPTransactionStatePending, got.State)
	assert.Empty(t, got.CertDER, "PENDING row must have no cert yet")
	assert.NotEmpty(t, got.CSRDER, "PENDING row must carry the CSR for the worker")
	assert.False(t, got.IsReenrollment)
}

// TestCMPTx_Select_NonDestructive verifies that pollReq's repeated lookups
// don't consume the row.
func TestCMPTx_Select_NonDestructive(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-poll-read"))
	require.NoError(t, repo.Insert(ctx, newTx(txID, "dms-poll", 5*time.Minute)))

	for i := 0; i < 3; i++ {
		_, ok, err := repo.Select(ctx, txID)
		require.NoError(t, err)
		require.Truef(t, ok, "Select call %d should still find the row", i+1)
	}

	// After three Selects the row must still be SelectAndDelete-able.
	_, ok, err := repo.SelectAndDelete(ctx, txID)
	require.NoError(t, err)
	assert.True(t, ok, "row must remain present after repeated Selects")
}

// TestCMPTx_Select_RespectsTTL verifies that Select hides expired rows.
func TestCMPTx_Select_RespectsTTL(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-select-expired"))
	require.NoError(t, repo.Insert(ctx, newTx(txID, "dms-poll", -1*time.Second)))

	_, ok, err := repo.Select(ctx, txID)
	require.NoError(t, err)
	assert.False(t, ok, "Select must not return expired rows")
}

// TestCMPTx_UpdateStateToIssued models the worker's happy path: it picks up a
// PENDING row, calls LWCEnroll, then writes the resulting cert back.
func TestCMPTx_UpdateStateToIssued(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-pend→issued"))
	require.NoError(t, repo.Insert(ctx, newPendingTx(txID, "dms-async", 5*time.Minute)))

	issuedCertDER := []byte("issued-cert-der-from-CA")
	require.NoError(t, repo.UpdateState(ctx, txID, storage.CMPTransactionStateIssued, issuedCertDER, ""))

	got, ok, err := repo.Select(ctx, txID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, storage.CMPTransactionStateIssued, got.State)
	assert.Equal(t, issuedCertDER, got.CertDER, "cert must be written into the row by UpdateState")
	assert.Empty(t, got.ErrorMessage)
}

// TestCMPTx_UpdateStateToFailed models the worker's error path: when LWCEnroll
// fails, the row stays around as ISSUE_FAILED with the reason so pollReq can
// surface a meaningful CMP error to the EE.
func TestCMPTx_UpdateStateToFailed(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-pend→failed"))
	require.NoError(t, repo.Insert(ctx, newPendingTx(txID, "dms-async", 5*time.Minute)))

	reason := "CA returned: profile validation failed"
	require.NoError(t, repo.UpdateState(ctx, txID, storage.CMPTransactionStateIssueFailed, nil, reason))

	got, ok, err := repo.Select(ctx, txID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, storage.CMPTransactionStateIssueFailed, got.State)
	assert.Empty(t, got.CertDER, "ISSUE_FAILED rows have no cert")
	assert.Equal(t, reason, got.ErrorMessage)
}

// TestCMPTx_UpdateState_IgnoresExpiredRow verifies that the worker's late
// write doesn't resurrect a row the janitor has already cleaned up. This is
// the race between DeleteExpired and the worker that prompted the
// "silently no-op when row is gone" contract.
func TestCMPTx_UpdateState_IgnoresExpiredRow(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	txID := hex.EncodeToString([]byte("tx-update-after-expiry"))
	require.NoError(t, repo.Insert(ctx, newPendingTx(txID, "dms-async", -1*time.Second)))

	// Row is already past expiry. UpdateState must return nil (no-op) without
	// either resurrecting the row or returning an error.
	require.NoError(t, repo.UpdateState(ctx, txID, storage.CMPTransactionStateIssued, []byte("late-cert"), ""))

	// And Select must continue to report the row as gone (expired).
	_, ok, err := repo.Select(ctx, txID)
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestCMPTx_SelectPending_ReturnsOldestFirst verifies the worker's queue
// behavior: it scans PENDING rows in creation order so older requests are
// processed before newer ones.
func TestCMPTx_SelectPending_ReturnsOldestFirst(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()

	older := newPendingTx(hex.EncodeToString([]byte("tx-older")), "dms-async", 5*time.Minute)
	older.CreatedAt = time.Now().Add(-2 * time.Minute)
	require.NoError(t, repo.Insert(ctx, older))

	newer := newPendingTx(hex.EncodeToString([]byte("tx-newer")), "dms-async", 5*time.Minute)
	newer.CreatedAt = time.Now().Add(-1 * time.Minute)
	require.NoError(t, repo.Insert(ctx, newer))

	pending, err := repo.SelectPending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assert.Equal(t, older.TransactionID, pending[0].TransactionID, "older PENDING row must come first")
	assert.Equal(t, newer.TransactionID, pending[1].TransactionID)
}

// TestCMPTx_SelectPending_IgnoresNonPendingAndExpired verifies the worker
// only sees rows it should actually process.
func TestCMPTx_SelectPending_IgnoresNonPendingAndExpired(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()

	require.NoError(t, repo.Insert(ctx, newTx(hex.EncodeToString([]byte("issued")), "dms-async", 5*time.Minute)))

	expired := newPendingTx(hex.EncodeToString([]byte("expired-pending")), "dms-async", -1*time.Second)
	require.NoError(t, repo.Insert(ctx, expired))

	failedTx := newPendingTx(hex.EncodeToString([]byte("failed")), "dms-async", 5*time.Minute)
	require.NoError(t, repo.Insert(ctx, failedTx))
	require.NoError(t, repo.UpdateState(ctx, failedTx.TransactionID, storage.CMPTransactionStateIssueFailed, nil, "nope"))

	alive := newPendingTx(hex.EncodeToString([]byte("alive-pending")), "dms-async", 5*time.Minute)
	require.NoError(t, repo.Insert(ctx, alive))

	pending, err := repo.SelectPending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1, "only the alive PENDING row should be returned")
	assert.Equal(t, alive.TransactionID, pending[0].TransactionID)
}

// TestCMPTx_SelectPending_RespectsLimit verifies the worker can fetch in
// batches without overwhelming the CA service.
func TestCMPTx_SelectPending_RespectsLimit(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		tx := newPendingTx(hex.EncodeToString([]byte(fmt.Sprintf("tx-batch-%d", i))), "dms-async", 5*time.Minute)
		tx.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
		require.NoError(t, repo.Insert(ctx, tx))
	}

	pending, err := repo.SelectPending(ctx, 3)
	require.NoError(t, err)
	assert.Len(t, pending, 3, "SelectPending must respect the limit")
}

// ---------------------------------------------------------------------------
// End async tests
// ---------------------------------------------------------------------------

// TestCMPTx_DeleteExpiredRemovesOnlyExpiredRows verifies the janitor query.
func TestCMPTx_DeleteExpiredRemovesOnlyExpiredRows(t *testing.T) {
	repo, cleanup := setupCMPTxRepo(t)
	defer cleanup()

	ctx := context.Background()
	liveID := hex.EncodeToString([]byte("tx-live"))
	expiredID := hex.EncodeToString([]byte("tx-old"))

	require.NoError(t, repo.Insert(ctx, newTx(liveID, "dms-e", 5*time.Minute)))
	require.NoError(t, repo.Insert(ctx, newTx(expiredID, "dms-e", -1*time.Second)))

	require.NoError(t, repo.DeleteExpired(ctx))

	// live row must still be there
	got, ok, err := repo.SelectAndDelete(ctx, liveID)
	require.NoError(t, err)
	assert.True(t, ok, "live transaction should survive DeleteExpired")
	assert.Equal(t, liveID, got.TransactionID)

	// expired row must be gone
	_, ok, err = repo.SelectAndDelete(ctx, expiredID)
	require.NoError(t, err)
	assert.False(t, ok, "expired transaction should have been deleted by DeleteExpired")
}
