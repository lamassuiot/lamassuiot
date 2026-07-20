package services

import (
	"context"
	"testing"
	"time"

	storage "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	mockservices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeDMSRepo is a minimal storage.DMSRepo stub that serves a single DMS.
type fakeDMSRepo struct{ dms *models.DMS }

func (f fakeDMSRepo) Count(ctx context.Context) (int, error) { return 1, nil }
func (f fakeDMSRepo) CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	return 1, nil
}
func (f fakeDMSRepo) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]any) (string, error) {
	return "", nil
}
func (f fakeDMSRepo) SelectExists(ctx context.Context, ID string) (bool, *models.DMS, error) {
	if f.dms != nil && f.dms.ID == ID {
		return true, f.dms, nil
	}
	return false, nil, nil
}
func (f fakeDMSRepo) Update(ctx context.Context, dms *models.DMS) (*models.DMS, error) {
	return dms, nil
}
func (f fakeDMSRepo) Insert(ctx context.Context, dms *models.DMS) (*models.DMS, error) {
	return dms, nil
}
func (f fakeDMSRepo) Delete(ctx context.Context, ID string) error { return nil }

// approvalCapturingCMPTxRepo serves one PENDING transaction and records the
// expiry ApproveCMPTransaction persists via UpdateState.
type approvalCapturingCMPTxRepo struct {
	noopCMPTxRepo
	tx             storage.CMPTransaction
	capturedExpiry time.Time
}

func (r *approvalCapturingCMPTxRepo) SelectIncludingExpired(ctx context.Context, transactionID string) (storage.CMPTransaction, bool, error) {
	if transactionID == r.tx.TransactionID {
		return r.tx, true, nil
	}
	return storage.CMPTransaction{}, false, nil
}

func (r *approvalCapturingCMPTxRepo) UpdateState(ctx context.Context, transactionID string, state storage.CMPTransactionState, cert *models.X509Certificate, errorMessage string, expiresAt time.Time) (bool, error) {
	r.capturedExpiry = expiresAt
	return true, nil
}

func newApproveTestSubject(t *testing.T, confirmationTimeout time.Duration) (*DMSManagerServiceBackend, *approvalCapturingCMPTxRepo, *fakeDMSManagerService) {
	t.Helper()
	dms := &models.DMS{
		ID: "dms-A",
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentCA: "test-ca",
				EnrollmentOptionsLWCRFC9483: models.EnrollmentOptionsLWCRFC9483{
					Workflow:            models.CMPWorkflowPhased,
					ConfirmationTimeout: models.TimeDuration(confirmationTimeout),
				},
			},
		},
	}
	txRepo := &approvalCapturingCMPTxRepo{
		tx: storage.CMPTransaction{
			TransactionID: "aabbccdd00112233",
			DMSID:         "dms-A",
			State:         storage.CMPTransactionStatePending,
			CSR:           (*models.X509CertificateRequest)(makeTestCSR(t, "phased-device")),
			CreatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
		},
	}
	dmsMock := &fakeDMSManagerService{
		MockDMSManagerService: &mockservices.MockDMSManagerService{},
		dms:                   dms,
	}
	svc := &DMSManagerServiceBackend{
		logger:       logrus.NewEntry(logrus.New()),
		dmsStorage:   fakeDMSRepo{dms: dms},
		cmptxStorage: txRepo,
	}
	svc.service = dmsMock
	return svc, txRepo, dmsMock
}

// TestApproveCMPTransaction_FloorsDeliveryWindow verifies the post-approval
// expiry is never shorter than cmpApprovalMinDeliveryWindow. A polling EE is
// only told to retry every 60s (the controller's pollRep checkAfter hint), so
// re-basing the row to a sub-minute ConfirmationTimeout used to let the
// confirmation monitor revoke the approved cert before the device was even
// allowed to poll for it.
func TestApproveCMPTransaction_FloorsDeliveryWindow(t *testing.T) {
	svc, txRepo, dmsMock := newApproveTestSubject(t, 10*time.Second)

	issuedCert, _ := makeTestCA(t)
	dmsMock.On("LWCEnroll", mock.Anything, mock.Anything, "dms-A", mock.Anything).Return(issuedCert, nil)

	before := time.Now()
	updated, err := svc.ApproveCMPTransaction(context.Background(), services.ApproveCMPTransactionInput{
		DMSID:         "dms-A",
		TransactionID: "aabbccdd00112233",
	})
	require.NoError(t, err)
	require.Equal(t, storage.CMPTransactionStateIssued, updated.State)

	minExpected := before.Add(cmpApprovalMinDeliveryWindow)
	require.False(t, txRepo.capturedExpiry.Before(minExpected.Add(-2*time.Second)),
		"post-approval expiry %s must be floored to at least %s so a 60s-interval poller can fetch the cert",
		txRepo.capturedExpiry, minExpected)
}

// TestApproveCMPTransaction_KeepsLongerConfirmationTimeout confirms the floor
// only lengthens short windows: a DMS-configured ConfirmationTimeout longer
// than the floor is applied as-is.
func TestApproveCMPTransaction_KeepsLongerConfirmationTimeout(t *testing.T) {
	confTimeout := 10 * time.Minute
	svc, txRepo, dmsMock := newApproveTestSubject(t, confTimeout)

	issuedCert, _ := makeTestCA(t)
	dmsMock.On("LWCEnroll", mock.Anything, mock.Anything, "dms-A", mock.Anything).Return(issuedCert, nil)

	before := time.Now()
	_, err := svc.ApproveCMPTransaction(context.Background(), services.ApproveCMPTransactionInput{
		DMSID:         "dms-A",
		TransactionID: "aabbccdd00112233",
	})
	require.NoError(t, err)

	require.False(t, txRepo.capturedExpiry.Before(before.Add(confTimeout).Add(-2*time.Second)),
		"a ConfirmationTimeout above the floor must be honored unchanged")
}
