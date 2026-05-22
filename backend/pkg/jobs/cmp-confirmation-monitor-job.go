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

// cmpConfirmationBatchSize caps how many expired ISSUED CMP transactions are
// processed per Run() so a backlog after a long outage does not turn into a
// single multi-minute revocation burst that starves the CA service.
const cmpConfirmationBatchSize = 100

// CMPConfirmationMonitor scans CMP transactions in ISSUED state whose
// confirmation window has elapsed without the EE sending certConf (or
// completing pollReq → certConf for explicit-confirm DMSs). Per RFC 4210 §5.2.8
// an unconfirmed enrollment is effectively rejected by the EE: the cert it
// references must be considered untrusted because no party has acknowledged
// receipt. This job revokes those certificates at the CA layer with
// cessationOfOperation and transitions the transaction row to REVOKED so the
// management UI shows the full lifecycle instead of an "ACTIVE" cert that no
// device actually holds.
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

	txs, err := m.txStore.SelectExpiredIssued(ctx, cmpConfirmationBatchSize)
	if err != nil {
		lFunc.Errorf("could not list expired ISSUED CMP transactions: %v", err)
		return
	}

	if len(txs) == 0 {
		lFunc.Debugf("no expired ISSUED transactions; nothing to revoke. Took %s", time.Since(start))
		return
	}

	lFunc.Infof("found %d expired ISSUED CMP transaction(s) to revoke", len(txs))
	for _, tx := range txs {
		m.revokeUnconfirmed(ctx, lFunc, tx)
	}

	lFunc.Infof("ended CMP confirmation-timeout check. Took %s", time.Since(start))
}

// revokeUnconfirmed handles a single ISSUED+expired transaction:
//   - revokes the cert at the CA (cessationOfOperation per RFC 5280 §5.3.1 —
//     the device never acknowledged the cert so it is effectively out of service)
//   - flips the transaction row to REVOKED so the row persists for audit
//
// Errors are logged but never returned: each row is independent, so a single
// CA failure must not stop the rest of the batch.
func (m *CMPConfirmationMonitor) revokeUnconfirmed(ctx context.Context, lFunc *logrus.Entry, tx storage.CMPTransaction) {
	lFunc = lFunc.
		WithField("cmp-tx", tx.TransactionID).
		WithField("dms", tx.DMSID).
		WithField("cert-sn", tx.CertSerialNumber).
		WithField("device-cn", tx.SubjectCommonName)

	if tx.CertSerialNumber == "" {
		// Defensive: an ISSUED row without a cert serial is malformed; we
		// cannot revoke anything, so just transition the row so it is not
		// retried on every tick.
		lFunc.Warnf("ISSUED transaction has no cert serial; marking REVOKED without CA revocation")
		if err := m.txStore.MarkRevokedByTransactionID(ctx, tx.TransactionID); err != nil {
			lFunc.Warnf("could not mark transaction REVOKED: %v", err)
			return
		}
		m.reportRejected(ctx, lFunc, tx, "ISSUED transaction had no cert serial; row marked REVOKED without CA revocation")
		return
	}

	_, err := m.caService.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
		SerialNumber:     tx.CertSerialNumber,
		NewStatus:        models.StatusRevoked,
		RevocationReason: ocsp.CessationOfOperation,
	})
	if err != nil {
		lFunc.Warnf("could not revoke unconfirmed cert: %v", err)
		// Do NOT transition the transaction row in this case — leaving it as
		// ISSUED+expired ensures the next tick retries the revocation rather
		// than silently dropping the unconfirmed cert.
		return
	}

	if err := m.txStore.MarkRevokedByTransactionID(ctx, tx.TransactionID); err != nil {
		// The cert is already revoked at the CA; failing to update the row
		// is recoverable on the next tick (MarkRevokedByTransactionID is
		// idempotent: the row will be marked again, both sides land on REVOKED).
		lFunc.Warnf("revoked at CA but could not mark transaction REVOKED: %v", err)
		return
	}

	reason := fmt.Sprintf(
		"certConf wait time expired at %s without receipt; certificate %s revoked with cessationOfOperation",
		tx.ExpiresAt.UTC().Format(time.RFC3339), tx.CertSerialNumber,
	)
	m.reportRejected(ctx, lFunc, tx, reason)

	lFunc.Infof("revoked unconfirmed cert and marked transaction REVOKED")
}

// reportRejected pushes a Rejected transition into WFX so the workflow view
// reflects the revocation. The WFX call is best-effort: the Lamassu-side
// revocation has already succeeded by the time we get here, so a WFX failure
// must not turn into a job error — it's logged and dropped. Skipped silently
// when WFX integration is disabled (m.wfx == nil).
func (m *CMPConfirmationMonitor) reportRejected(ctx context.Context, lFunc *logrus.Entry, tx storage.CMPTransaction, reason string) {
	if m.wfx == nil {
		return
	}
	transition := cmpwfx.CMPTransition{
		TransactionID:     tx.TransactionID,
		DMSID:             tx.DMSID,
		RequestType:       tx.RequestType,
		SubjectCommonName: tx.SubjectCommonName,
		CertSerialNumber:  tx.CertSerialNumber,
		State:             cmpwfx.CMPStateRejected,
		Reason:            reason,
		Metadata: map[string]any{
			"rejectionSource": "cmp-confirmation-monitor",
			"expiresAt":       tx.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}
	if _, err := m.wfx.Emit(ctx, transition); err != nil {
		lFunc.Warnf("could not emit WFX Rejected transition: %v", err)
	}
}
