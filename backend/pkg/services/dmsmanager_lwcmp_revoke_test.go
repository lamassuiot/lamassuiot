package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	mockservices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Security regression test: a CMP self-revocation (rr where the protection
// signer's serial equals the target certificate's serial) MUST NOT be
// authorized merely because the attacker-supplied signer certificate's
// fields are internally self-consistent. The signer MUST also chain to a CA
// this DMS trusts — otherwise anyone who has observed a target certificate's
// (non-secret) serial number and issuer name could mint their own self-signed
// certificate asserting the same serial and revoke it. See LWCRevokeCertificate
// in dmsmanager_lwcmp.go.

// noopCMPTxRepo is a minimal storage.CMPTransactionRepo stub: every query
// reports "nothing pending" so LWCRevokeCertificate's downstream checks
// (HasUnconfirmedReenrollment) never block the revocation under test.
type noopCMPTxRepo struct{}

func (noopCMPTxRepo) Exists(ctx context.Context, transactionID string) (bool, error) {
	return false, nil
}
func (noopCMPTxRepo) HasUnconfirmedReenrollment(ctx context.Context, dmsID, supersededCertSerial string) (bool, error) {
	return false, nil
}
func (noopCMPTxRepo) HasAbandonedReenrollment(ctx context.Context, dmsID, supersededCertSerial string) (bool, error) {
	return false, nil
}
func (noopCMPTxRepo) HasSeenRegToken(ctx context.Context, dmsID, regToken string) (bool, error) {
	return false, nil
}
func (noopCMPTxRepo) Insert(ctx context.Context, tx models.CMPTransaction) error { return nil }
func (noopCMPTxRepo) Select(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	return models.CMPTransaction{}, false, nil
}
func (noopCMPTxRepo) SelectIncludingExpired(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	return models.CMPTransaction{}, false, nil
}
func (noopCMPTxRepo) SelectAndDelete(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	return models.CMPTransaction{}, false, nil
}
func (noopCMPTxRepo) ClaimPending(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	return models.CMPTransaction{}, false, nil
}
func (noopCMPTxRepo) WithDeviceLock(ctx context.Context, deviceID string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
func (noopCMPTxRepo) ClaimIssuedForRevocation(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	return models.CMPTransaction{}, false, nil
}
func (noopCMPTxRepo) Confirm(ctx context.Context, transactionID string) (models.CMPTransaction, models.CMPTransactionState, bool, error) {
	return models.CMPTransaction{}, "", false, nil
}
func (noopCMPTxRepo) UpdateState(ctx context.Context, transactionID string, state models.CMPTransactionState, cert *models.X509Certificate, errorMessage string, expiresAt time.Time) (bool, error) {
	return false, nil
}
func (noopCMPTxRepo) MarkRevokedByCertSerial(ctx context.Context, certSerialNumber string) error {
	return nil
}
func (noopCMPTxRepo) SelectByCertSerial(ctx context.Context, certSerialNumber string) (models.CMPTransaction, bool, error) {
	return models.CMPTransaction{}, false, nil
}
func (noopCMPTxRepo) SelectExpiredIssued(ctx context.Context, limit int) ([]models.CMPTransaction, error) {
	return nil, nil
}
func (noopCMPTxRepo) MarkRevokedByTransactionID(ctx context.Context, transactionID string) error {
	return nil
}
func (noopCMPTxRepo) SelectPending(ctx context.Context, limit int) ([]models.CMPTransaction, error) {
	return nil, nil
}
func (noopCMPTxRepo) SelectExpiredPending(ctx context.Context, limit int) ([]models.CMPTransaction, error) {
	return nil, nil
}
func (noopCMPTxRepo) DeleteExpired(ctx context.Context) error { return nil }
func (noopCMPTxRepo) SelectAllByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.CMPTransaction), queryParams *resources.QueryParameters) (string, error) {
	return "", nil
}

// makeTestCA creates a self-signed CA certificate/key pair.
func makeTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// makeTestLeaf issues a leaf certificate signed by (caCert, caKey) with the
// given serial number.
func makeTestLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// makeForgedSelfSignedCert builds a self-signed certificate (NOT issued by
// any trusted CA) carrying the given serial number — simulating an attacker
// who knows a target certificate's (public) serial number and crafts their
// own certificate asserting it, without possessing the real device's key.
func makeForgedSelfSignedCert(t *testing.T, cn string, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func dmsForRevokeTest(id string) *models.DMS {
	// Resolved via models.ResolveCMPSettings (mirroring what the real
	// GetDMSByID/fakeDMSManagerService pairing does in production) so RR's
	// RFC011 defaults (Authorization=self_only, AllowExpiredTarget=true,
	// TrustedRA.RequireCMCRAEKU=true, AllowedReasons=[unspecified,
	// key_compromise, cessation_of_operation, superseded]) are populated —
	// a bare zero-value RR{} would reject every revocation via the new
	// AllowedReasons allow-list gate before a test's actual scenario runs.
	settings := models.ResolveCMPSettings(models.DMSSettings{
		EnrollmentSettings: models.EnrollmentSettings{
			EnrollmentProtocol: models.CMP,
			EnrollmentCA:       "test-ca",
			EnrollmentOptionsLWCRFC9483: models.EnrollmentOptionsLWCRFC9483{
				AuthMode: models.CMPAuthModeClientCertificate,
			},
		},
	})
	return &models.DMS{
		ID:       id,
		Settings: settings,
	}
}

func newRevokeTestSubject(t *testing.T, dms *models.DMS) (*DMSManagerServiceBackend, *mockservices.MockCAService) {
	t.Helper()
	caMock := &mockservices.MockCAService{}
	dmsMock := &fakeDMSManagerService{
		MockDMSManagerService: &mockservices.MockDMSManagerService{},
		dms:                   dms,
	}
	svc := &DMSManagerServiceBackend{
		caClient:     caMock,
		logger:       logrus.NewEntry(logrus.New()),
		cmptxStorage: noopCMPTxRepo{},
	}
	svc.service = dmsMock
	return svc, caMock
}

// TestLWCRevokeCertificate_SelfRevocation_RejectsForgedSelfSignedCert is the
// critical regression test: a self-signed certificate that merely claims the
// target's serial number (matching input.SerialNumber, so the "self
// revocation" branch is taken) but does NOT chain to the DMS's trusted CA
// must be rejected. Before the fix, this branch only checked internal
// self-consistency of attacker-controlled fields and never validated the
// signer certificate against any CA, allowing exactly this forgery to revoke
// an arbitrary certificate by serial number.
func TestLWCRevokeCertificate_SelfRevocation_RejectsForgedSelfSignedCert(t *testing.T) {
	dms := dmsForRevokeTest("dms-A")
	svc, caMock := newRevokeTestSubject(t, dms)

	caCert, _ := makeTestCA(t)
	targetSerial := big.NewInt(424242)
	forged := makeForgedSelfSignedCert(t, "victim-device", targetSerial)

	caMock.On("GetCAByID", mock.Anything, services.GetCAByIDInput{CAID: "test-ca"}).
		Return(&models.CACertificate{
			Certificate: models.Certificate{Certificate: (*models.X509Certificate)(caCert)},
		}, nil)

	err := svc.LWCRevokeCertificate(context.Background(), services.RevokeCertificateInput{
		APS:          "dms-A",
		SerialNumber: helpers.SerialNumberToHexString(targetSerial),
	}, forged)

	require.Error(t, err, "a forged self-signed certificate must not authorize revocation")
	caMock.AssertNotCalled(t, "GetCertificateBySerialNumber", mock.Anything, mock.Anything)
	caMock.AssertNotCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
}

// TestLWCRevokeCertificate_SelfRevocation_AllowsCAValidatedCert confirms the
// fix does not break the legitimate case: a signer certificate that genuinely
// chains to the DMS's trusted CA and matches the target serial is authorized.
func TestLWCRevokeCertificate_SelfRevocation_AllowsCAValidatedCert(t *testing.T) {
	dms := dmsForRevokeTest("dms-A")
	svc, caMock := newRevokeTestSubject(t, dms)

	caCert, caKey := makeTestCA(t)
	targetSerial := big.NewInt(555)
	real := makeTestLeaf(t, caCert, caKey, "real-device", targetSerial)
	targetSerialHex := helpers.SerialNumberToHexString(targetSerial)

	caMock.On("GetCAByID", mock.Anything, services.GetCAByIDInput{CAID: "test-ca"}).
		Return(&models.CACertificate{
			Certificate: models.Certificate{Certificate: (*models.X509Certificate)(caCert)},
		}, nil)
	caMock.On("GetCertificateBySerialNumber", mock.Anything, services.GetCertificatesBySerialNumberInput{SerialNumber: targetSerialHex}).
		Return(&models.Certificate{SerialNumber: targetSerialHex, Status: models.StatusActive}, nil)
	caMock.On("UpdateCertificateStatus", mock.Anything, mock.MatchedBy(func(in services.UpdateCertificateStatusInput) bool {
		return in.SerialNumber == targetSerialHex && in.NewStatus == models.StatusRevoked
	})).Return(&models.Certificate{SerialNumber: targetSerialHex, Status: models.StatusRevoked}, nil)

	err := svc.LWCRevokeCertificate(context.Background(), services.RevokeCertificateInput{
		APS:          "dms-A",
		SerialNumber: targetSerialHex,
	}, real)

	require.NoError(t, err)
	caMock.AssertCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
}
