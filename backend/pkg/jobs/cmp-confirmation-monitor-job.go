package jobs

import (
	"context"
	"fmt"
	"time"

	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

// cmpConfirmationBatchSize caps how many expired AwaitingCertConf CMP transactions are
// processed per Run() so a backlog after a long outage does not turn into a
// single multi-minute revocation burst that starves the CA service.
const cmpConfirmationBatchSize = 100

// cmpExpiredPendingRetention is how long an expired approval/PoP row sticks
// around in Expired state after its window elapses. Long enough for
// operators to notice and for a polling EE to receive the rejection reason,
// short enough that DeleteExpired keeps the table bounded.
const cmpExpiredPendingRetention = 7 * 24 * time.Hour

// CMPConfirmationMonitor scans CMP transactions in AwaitingCertConf state whose
// confirmation window has elapsed without the EE sending certConf (or
// completing pollReq → certConf for explicit-confirm DMSs). Per RFC 4210 §5.2.8
// an unconfirmed enrollment is effectively rejected by the EE: the cert it
// references must be considered untrusted because no party has acknowledged
// receipt. This job revokes those certificates at the CA layer with
// cessationOfOperation and transitions the transaction row to REVOKED so the
// management UI shows the full lifecycle instead of an "ACTIVE" cert that no
// device actually holds. Every state change it makes is mirrored into WFX with
// the same state name (Revoking, Revoked, Expired, ...).
//
// It mirrors the structure of CryptoMonitor (ca-crypto-monitor-job.go) so
// operators get the same enabled/frequency configuration knobs.
type CMPConfirmationMonitor struct {
	logger    *logrus.Entry
	txStore   storage.CMPTransactionRepo
	caService services.CAService
	// wfx is optional — when nil, no WFX transitions are emitted (e.g. WFX
	// integration disabled in config). When set, every expired-unconfirmed
	// transaction is also pushed into the workflow as Rejected so the workflow
	// view in WFX stays in sync with the Lamassu transaction table.
	wfx cmpwfx.CMPReporter
}

func NewCMPConfirmationMonitor(txStore storage.CMPTransactionRepo, caService services.CAService, wfx cmpwfx.CMPReporter, logger *logrus.Entry) *CMPConfirmationMonitor {
	return &CMPConfirmationMonitor{
		logger:    logger,
		txStore:   txStore,
		caService: caService,
		wfx:       wfx,
	}
}

func (m *CMPConfirmationMonitor) Run() {
	ctx := helpers.InitContext()
	lFunc := helpers.ConfigureLogger(ctx, m.logger)

	start := time.Now()
	lFunc.Info("starting periodic CMP confirmation-timeout check")

	// 1) Expired AwaitingCertConf — certs issued but never confirmed by the EE.
	// Revoke at the CA, mark the row Revoked.
	issuedTxs, err := m.txStore.SelectExpiredIssued(ctx, cmpConfirmationBatchSize)
	if err != nil {
		lFunc.Errorf("could not list expired AwaitingCertConf CMP transactions: %v", err)
	} else if len(issuedTxs) > 0 {
		lFunc.Infof("found %d expired AwaitingCertConf CMP transaction(s) to revoke", len(issuedTxs))
		for _, tx := range issuedTxs {
			m.revokeUnconfirmed(ctx, lFunc, tx)
		}
	}

	// 2) Expired AwaitingApproval/AwaitingPoPResponse — phased-workflow requests
	// the admin never acted on and PoP challenges the EE never answered.
	// Transition to Expired with a descriptive reason and a fresh
	// retention TTL so DeleteExpired sweeps them later. This keeps the
	// rejection visible to operators and lets a stragglers' pollReq see the
	// real cause instead of "unknown transactionID".
	pendingTxs, err := m.txStore.SelectExpiredPending(ctx, cmpConfirmationBatchSize)
	if err != nil {
		lFunc.Errorf("could not list expired approval/PoP CMP transactions: %v", err)
	} else if len(pendingTxs) > 0 {
		lFunc.Infof("found %d expired approval/PoP CMP transaction(s) to mark Expired", len(pendingTxs))
		for _, tx := range pendingTxs {
			m.expireUnapproved(ctx, lFunc, tx)
		}
	}

	lFunc.Infof("ended CMP confirmation-timeout check. Took %s", time.Since(start))
}

// revokeUnconfirmed handles a single AwaitingCertConf(-or-Revoking)+expired transaction:
//   - atomically claims the row (AwaitingCertConf → Revoking, or re-claims one left
//     in Revoking by a failed attempt) so a legitimate certConf/
//     implicit-confirm pollReq racing this same tick (both use Confirm,
//     AwaitingCertConf → Confirmed/LogicallyComplete) cannot lose to us — Confirm and
//     ClaimIssuedForRevocation both require state=AwaitingCertConf, so at most one
//     of them ever wins for a given row; if the EE just confirmed, the claim
//     here fails and this transaction is left alone entirely (no CA call)
//   - revokes the cert at the CA (cessationOfOperation per RFC 5280 §5.3.1 —
//     the device never acknowledged the cert so it is effectively out of service)
//   - flips the transaction row to Revoked so the row persists for audit
//
// Errors are logged but never returned: each row is independent, so a single
// CA failure must not stop the rest of the batch.
func (m *CMPConfirmationMonitor) revokeUnconfirmed(ctx context.Context, lFunc *logrus.Entry, tx models.CMPTransaction) {
	lFunc = lFunc.
		WithField("cmp-tx", tx.TransactionID).
		WithField("dms", tx.DMSID).
		WithField("cert-sn", tx.CertSerialNumber).
		WithField("device-cn", tx.SubjectCommonName)

	claimed, ok, err := m.txStore.ClaimIssuedForRevocation(ctx, tx.TransactionID)
	if err != nil {
		lFunc.Warnf("could not claim transaction for revocation: %v", err)
		return
	}
	if !ok {
		// The row is no longer AwaitingCertConf — most likely a certConf (or an
		// implicit-confirm pollReq) legitimately confirmed it, or it was
		// already claimed/finalized by another replica's tick. Either way,
		// this transaction is not ours to touch.
		lFunc.Debugf("transaction is no longer AwaitingCertConf (already confirmed/claimed/finalized); skipping revocation")
		return
	}
	// Only the first claim moves the WFX job (AwaitingCertConf → Revoking); a
	// re-claim of a row still in Revoking from a failed attempt is not a new
	// transition.
	firstClaim := tx.State == models.CMPTransactionStateAwaitingCertConf
	tx = claimed
	if firstClaim {
		m.report(ctx, lFunc, tx, cmpwfx.CMPStateRevoking, "confirmation window elapsed without certConf; revoking the certificate", "")
	}

	if tx.CertSerialNumber == "" {
		// Defensive: an AwaitingCertConf row without a cert serial is malformed; we
		// cannot revoke anything, so just transition the row so it is not
		// retried on every tick.
		lFunc.Warnf("AwaitingCertConf transaction has no cert serial; marking Revoked without CA revocation")
		if err := m.txStore.MarkRevokedByTransactionID(ctx, tx.TransactionID); err != nil {
			lFunc.Warnf("could not mark transaction Revoked: %v", err)
			return
		}
		m.report(ctx, lFunc, tx, cmpwfx.CMPStateRevoked, "transaction had no cert serial; row marked Revoked without CA revocation", "")
		return
	}

	_, err = m.caService.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
		SerialNumber:     tx.CertSerialNumber,
		NewStatus:        models.StatusRevoked,
		RevocationReason: ocsp.CessationOfOperation,
	})
	if err != nil {
		lFunc.Warnf("could not revoke unconfirmed cert: %v", err)
		// Leave the row in Revoking (still expired): the next tick's
		// SelectExpiredIssued picks it up again and ClaimIssuedForRevocation
		// re-claims it, so the revocation is retried rather than the
		// unconfirmed cert being silently dropped. Revoking is the honest state —
		// the certificate is being revoked, and the row can no longer be confirmed.
		return
	}

	if err := m.txStore.MarkRevokedByTransactionID(ctx, tx.TransactionID); err != nil {
		// The cert is already revoked at the CA; failing to update the row
		// is recoverable on the next tick (MarkRevokedByTransactionID is
		// idempotent: the row will be marked again, both sides land on Revoked).
		lFunc.Warnf("revoked at CA but could not mark transaction Revoked: %v", err)
		return
	}

	reason := fmt.Sprintf(
		"certConf wait time expired at %s without receipt; certificate %s revoked with cessationOfOperation",
		tx.ExpiresAt.UTC().Format(time.RFC3339), tx.CertSerialNumber,
	)
	m.report(ctx, lFunc, tx, cmpwfx.CMPStateRevoked, reason, "cmp-confirmation-monitor")

	lFunc.Infof("revoked unconfirmed cert and marked transaction Revoked")
}

// expireUnapproved handles a single AwaitingApproval/Approving/AwaitingPoPResponse
// +expired transaction by transitioning it to Expired with a reason describing
// the timeout. The row is given a retention TTL (cmpExpiredPendingRetention) so
// DeleteExpired eventually sweeps it; until then a late pollReq sees the
// outcome via the existing Expired branch in handlePoll and operators
// can inspect the row in the management UI.
func (m *CMPConfirmationMonitor) expireUnapproved(ctx context.Context, lFunc *logrus.Entry, tx models.CMPTransaction) {
	lFunc = lFunc.
		WithField("cmp-tx", tx.TransactionID).
		WithField("dms", tx.DMSID).
		WithField("device-cn", tx.SubjectCommonName)

	reason := fmt.Sprintf(
		"approval window expired at %s without administrator action",
		tx.ExpiresAt.UTC().Format(time.RFC3339),
	)
	if tx.State == models.CMPTransactionStateAwaitingPoPResponse {
		reason = fmt.Sprintf(
			"proof-of-possession challenge window expired at %s without a valid popdecr",
			tx.ExpiresAt.UTC().Format(time.RFC3339),
		)
	}
	updated, err := m.txStore.UpdateState(
		ctx, tx.TransactionID,
		models.CMPTransactionStateExpired,
		nil, reason,
		time.Now().Add(cmpExpiredPendingRetention),
	)
	if err != nil {
		lFunc.Warnf("could not mark expired transaction as Expired: %v", err)
		return
	}
	if !updated {
		// Concurrent admin action (approve/reject) reached the row before us;
		// no further work is needed.
		lFunc.Debugf("expired transaction already transitioned by another worker")
		return
	}

	m.report(ctx, lFunc, tx, cmpwfx.CMPStateExpired, reason, "cmp-confirmation-monitor")
	lFunc.Infof("marked expired %s transaction Expired", tx.State)
}

// report mirrors one state change into WFX under the same state name. The WFX
// call is best-effort: the Lamassu-side change has already succeeded by the
// time we get here, so a WFX failure must not turn into a job error — it's
// logged and dropped. Skipped silently when WFX integration is disabled
// (m.wfx == nil). The transition carries no Workflow: the reporter finds the
// transaction's job in whichever CMP workflow holds it.
func (m *CMPConfirmationMonitor) report(ctx context.Context, lFunc *logrus.Entry, tx models.CMPTransaction, state cmpwfx.CMPState, reason, source string) {
	if m.wfx == nil {
		return
	}
	metadata := map[string]any{"expiresAt": tx.ExpiresAt.UTC().Format(time.RFC3339)}
	if source != "" {
		metadata["source"] = source
	}
	transition := cmpwfx.CMPTransition{
		TransactionID:     tx.TransactionID,
		DMSID:             tx.DMSID,
		RequestType:       tx.RequestType,
		SubjectCommonName: tx.SubjectCommonName,
		CertSerialNumber:  tx.CertSerialNumber,
		State:             state,
		Reason:            reason,
		Metadata:          metadata,
	}
	if _, err := m.wfx.Emit(ctx, transition); err != nil {
		lFunc.Warnf("could not emit WFX %s transition: %v", state, err)
	}
}
