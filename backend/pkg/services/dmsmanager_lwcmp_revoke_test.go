package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
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
func (noopCMPTxRepo) ClaimRegToken(ctx context.Context, dmsID, regToken string) (bool, error) {
	return true, nil
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

// TestCMPRevocationReasonName_CoversEveryRequestableReason is a regression test
// for a silent policy bypass in the RR.AllowedReasons allow-list.
//
// The gate in LWCRevokeCertificate reads:
//
//	if name, ok := cmpRevocationReasonName(input.Reason); ok && !cmpReasonAllowed(...)
//
// so a CRLReason the mapper does not recognise (ok == false) skips the allow-list
// entirely rather than being rejected by it. certificateHold(6),
// privilegeWithdrawn(9) and aaCompromise(10) all used to fall in that hole while
// still being accepted on the wire by corecmp.IsKnownCRLReason — meaning an
// operator who restricted AllowedReasons to, say, {unspecified} could still have
// any EE revoke with reason 9 or 10.
//
// certificateHold(6) and removeFromCRL(8) are the deliberate exceptions: both
// belong to the suspend/resume lifecycle governed by RR.AllowRevival rather than
// to this list of permanent revocation reasons. See
// TestLWCRevokeCertificate_CertificateHold_NotGatedByAllowedReasons.
func TestCMPRevocationReasonName_CoversEveryRequestableReason(t *testing.T) {
	expected := map[int]models.CMPRevocationReason{
		0:  models.CMPRevocationReasonUnspecified,
		1:  models.CMPRevocationReasonKeyCompromise,
		2:  models.CMPRevocationReasonCACompromise,
		3:  models.CMPRevocationReasonAffiliationChanged,
		4:  models.CMPRevocationReasonSuperseded,
		5:  models.CMPRevocationReasonCessationOfOperation,
		9:  models.CMPRevocationReasonPrivilegeWithdrawn,
		10: models.CMPRevocationReasonAACompromise,
	}

	for code, want := range expected {
		got, ok := cmpRevocationReasonName(models.RevocationReason(code))
		require.Truef(t, ok, "CRLReason %d must map to an allow-list name, else RR.AllowedReasons silently ignores it", code)
		require.Equalf(t, want, got, "CRLReason %d mapped to the wrong allow-list name", code)
	}

	// The suspend/resume pair is intentionally unmapped — governed by AllowRevival.
	for _, code := range []int{6, 8} {
		_, ok := cmpRevocationReasonName(models.RevocationReason(code))
		require.Falsef(t, ok,
			"CRLReason %d belongs to the hold/release lifecycle governed by RR.AllowRevival, not AllowedReasons", code)
	}

	// A reason that IS gated must be rejected when absent from the allow-list.
	require.False(t,
		cmpReasonAllowed(models.CMPRevocationReasonPrivilegeWithdrawn, []models.CMPRevocationReason{models.CMPRevocationReasonUnspecified}),
		"privilegeWithdrawn must not be permitted by an allow-list that omits it")
}

// makeTestRALeaf builds a leaf certificate carrying id-kp-cmcRA, i.e. one that
// passes validateTrustedRASigner once it chains to a DMS-trusted CA.
func makeTestRALeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{chelpers.OidExtKeyUsageCMCRA},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// dmsAllowingTrustedRARevocation is dmsForRevokeTest with RR.Authorization set to
// self_and_trusted_ra, so a third-party (RA) revocation reaches the ownership
// check instead of being refused by the self_only gate first.
func dmsAllowingTrustedRARevocation(id string) *models.DMS {
	dms := dmsForRevokeTest(id)
	dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.RR.Authorization =
		models.CMPRevocationAuthorizationSelfTrustedRA
	return dms
}

// TestLWCRevokeCertificate_TrustedRA_UnownedCertificateRejected is a security
// regression test for a fail-open in the cross-DMS ownership check.
//
// The check used to reject only when the target certificate's subject CN
// resolved to a device record owned by a DIFFERENT DMS. An empty CN, or a CN
// naming no registered device at all, skipped it entirely — so a trusted-RA
// signer authorized under DMS-A could revoke a certificate DMS-A has no
// authority over, simply by naming its serial number. Two DMSes sharing one
// EnrollmentCA (explicitly supported) makes this reachable: chain-validating the
// signer proves the SIGNER belongs to DMS-A, never that the TARGET does.
func TestLWCRevokeCertificate_TrustedRA_UnownedCertificateRejected(t *testing.T) {
	dms := dmsAllowingTrustedRARevocation("dms-A")
	svc, caMock := newRevokeTestSubject(t, dms)

	caCert, caKey := makeTestCA(t)
	// A trusted RA for dms-A: chains to the DMS's CA and carries id-kp-cmcRA.
	raSigner := makeTestRALeaf(t, caCert, caKey, "dms-a-ra", big.NewInt(7001))
	// The target is a different certificate, with no device record and no CMP
	// transaction row (noopCMPTxRepo returns not-found) — ownership unresolvable.
	targetSerial := big.NewInt(9002)
	targetSerialHex := helpers.SerialNumberToHexString(targetSerial)

	caMock.On("GetCAByID", mock.Anything, services.GetCAByIDInput{CAID: "test-ca"}).
		Return(&models.CACertificate{
			Certificate: models.Certificate{Certificate: (*models.X509Certificate)(caCert)},
		}, nil)
	caMock.On("GetCertificateBySerialNumber", mock.Anything, services.GetCertificatesBySerialNumberInput{SerialNumber: targetSerialHex}).
		Return(&models.Certificate{SerialNumber: targetSerialHex, Status: models.StatusActive}, nil)

	err := svc.LWCRevokeCertificate(context.Background(), services.RevokeCertificateInput{
		APS:          "dms-A",
		SerialNumber: targetSerialHex,
	}, raSigner)

	require.ErrorIs(t, err, errs.ErrCMPDeviceOwnedByOtherDMS,
		"a trusted RA must not revoke a certificate whose ownership this DMS cannot establish")
	caMock.AssertNotCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
}

// TestLWCRevokeCertificate_SelfRevocation_UnownedCertificateAllowed is the
// counterpart: failing closed must not break self-revocation of a certificate
// with no ownership record. This is what keeps legacy certificates and
// non-device subjects (p10cr, ccr cross-certificates) revocable by their holder,
// whose authority comes from being the target certificate itself — already
// chain-validated against the DMS's trusted CAs.
func TestLWCRevokeCertificate_SelfRevocation_UnownedCertificateAllowed(t *testing.T) {
	dms := dmsForRevokeTest("dms-A")
	svc, caMock := newRevokeTestSubject(t, dms)

	caCert, caKey := makeTestCA(t)
	targetSerial := big.NewInt(9003)
	targetSerialHex := helpers.SerialNumberToHexString(targetSerial)
	// Signer IS the target certificate, and its subject resolves to no device.
	self := makeTestLeaf(t, caCert, caKey, "not-a-registered-device", targetSerial)

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
	}, self)

	require.NoError(t, err, "self-revocation must remain possible without an ownership record")
	caMock.AssertCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
}

// TestLWCRevokeCertificate_CertificateHold_NotGatedByAllowedReasons pins that a
// certificateHold (CRLReason 6) revocation succeeds even on a DMS whose
// RR.AllowedReasons does not list it.
//
// certificateHold is a suspension, not a permanent revocation: its release is
// governed by RR.AllowRevival, so hold and release are one feature rather than an
// entry in this list. Bringing it under the AllowedReasons gate broke the RFC
// 9483 revive flow end to end — the CMP test suite's revive tests place a
// certificate on hold first, and both began failing at that step against a DMS
// whose allowed_reasons had been explicitly configured. It could not be repaired
// by changing defaults either, since resolveRR only fills a "fresh" RR block, so
// every already-configured deployment would have needed a manual config edit.
func TestLWCRevokeCertificate_CertificateHold_NotGatedByAllowedReasons(t *testing.T) {
	dms := dmsForRevokeTest("dms-A")
	// An explicitly configured list that deliberately omits any hold entry —
	// mirroring a real deployment's persisted settings.
	dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.RR.AllowedReasons =
		[]models.CMPRevocationReason{models.CMPRevocationReasonUnspecified}
	svc, caMock := newRevokeTestSubject(t, dms)

	caCert, caKey := makeTestCA(t)
	targetSerial := big.NewInt(6006)
	targetSerialHex := helpers.SerialNumberToHexString(targetSerial)
	self := makeTestLeaf(t, caCert, caKey, "hold-device", targetSerial)

	caMock.On("GetCAByID", mock.Anything, services.GetCAByIDInput{CAID: "test-ca"}).
		Return(&models.CACertificate{
			Certificate: models.Certificate{Certificate: (*models.X509Certificate)(caCert)},
		}, nil)
	caMock.On("GetCertificateBySerialNumber", mock.Anything, services.GetCertificatesBySerialNumberInput{SerialNumber: targetSerialHex}).
		Return(&models.Certificate{SerialNumber: targetSerialHex, Status: models.StatusActive}, nil)
	caMock.On("UpdateCertificateStatus", mock.Anything, mock.MatchedBy(func(in services.UpdateCertificateStatusInput) bool {
		return in.SerialNumber == targetSerialHex && in.NewStatus == models.StatusRevoked
	})).Return(&models.Certificate{SerialNumber: targetSerialHex, Status: models.StatusRevoked}, nil)

	// CRLReason 6 = certificateHold.
	err := svc.LWCRevokeCertificate(context.Background(), services.RevokeCertificateInput{
		APS:          "dms-A",
		SerialNumber: targetSerialHex,
		Reason:       models.RevocationReason(6),
	}, self)

	require.NoError(t, err, "certificateHold must not be gated by RR.AllowedReasons")
	caMock.AssertCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
}

// TestLWCRevokeCertificate_PrivilegeWithdrawn_GatedByAllowedReasons is the
// counterpart: privilegeWithdrawn (9) IS a permanent revocation reason with no
// other gate, so an allow-list that omits it must reject it. This is the half of
// the original bug that was genuinely a silent bypass.
func TestLWCRevokeCertificate_PrivilegeWithdrawn_GatedByAllowedReasons(t *testing.T) {
	dms := dmsForRevokeTest("dms-A")
	dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.RR.AllowedReasons =
		[]models.CMPRevocationReason{models.CMPRevocationReasonUnspecified}
	svc, caMock := newRevokeTestSubject(t, dms)

	caCert, caKey := makeTestCA(t)
	targetSerial := big.NewInt(6009)
	targetSerialHex := helpers.SerialNumberToHexString(targetSerial)
	self := makeTestLeaf(t, caCert, caKey, "privwd-device", targetSerial)

	caMock.On("GetCAByID", mock.Anything, services.GetCAByIDInput{CAID: "test-ca"}).
		Return(&models.CACertificate{
			Certificate: models.Certificate{Certificate: (*models.X509Certificate)(caCert)},
		}, nil)
	caMock.On("GetCertificateBySerialNumber", mock.Anything, services.GetCertificatesBySerialNumberInput{SerialNumber: targetSerialHex}).
		Return(&models.Certificate{SerialNumber: targetSerialHex, Status: models.StatusActive}, nil)

	// CRLReason 9 = privilegeWithdrawn.
	err := svc.LWCRevokeCertificate(context.Background(), services.RevokeCertificateInput{
		APS:          "dms-A",
		SerialNumber: targetSerialHex,
		Reason:       models.RevocationReason(9),
	}, self)

	require.ErrorIs(t, err, errs.ErrCertificateStatusTransitionNotAllowed,
		"privilegeWithdrawn must be rejected by an allow-list that omits it")
	caMock.AssertNotCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
}
