package ca

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// holdHierarchy is a root CA with a sub-CA, a certificate issued by the root and a certificate issued by the sub-CA.
type holdHierarchy struct {
	root, sub         *models.CACertificate
	rootCert, subCert string
	caSDK, caSvc      services.CAService
	t                 *testing.T
}

func newHoldHierarchy(t *testing.T) holdHierarchy {
	t.Helper()
	require.NoError(t, serverTest.BeforeEach())
	caTest := serverTest.CA

	root, err := initCA(caTest.Service)
	require.NoError(t, err)

	sub, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "hold-sub-ca"},
		CAExpiration: models.Validity{Type: models.Time, Time: root.Certificate.ValidTo},
		ParentID:     root.ID,
		ProfileID:    root.ProfileID,
	})
	require.NoError(t, err)

	h := holdHierarchy{root: root, sub: sub, caSDK: caTest.HttpCASDK, caSvc: caTest.Service, t: t}
	h.rootCert = h.issue(root.ID, "hold-root-leaf")
	h.subCert = h.issue(sub.ID, "hold-sub-leaf")
	return h
}

func (h holdHierarchy) issue(caID, cn string) string {
	h.t.Helper()
	cert, err := h.caSvc.CreateCertificate(context.Background(), services.CreateCertificateInput{
		CAID:    caID,
		KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject: models.Subject{CommonName: cn},
	})
	require.NoError(h.t, err)
	return cert.SerialNumber
}

func (h holdHierarchy) setCAStatus(caID string, status models.CertificateStatus, reason models.RevocationReason) {
	h.t.Helper()
	_, err := h.caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{CAID: caID, Status: status, RevocationReason: reason})
	require.NoError(h.t, err)
}

func (h holdHierarchy) setCertStatus(serial string, status models.CertificateStatus, reason models.RevocationReason) {
	h.t.Helper()
	_, err := h.caSDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{SerialNumber: serial, NewStatus: status, RevocationReason: reason})
	require.NoError(h.t, err)
}

func (h holdHierarchy) requireCA(caID string, status models.CertificateStatus, reason models.RevocationReason) {
	h.t.Helper()
	ca, err := h.caSvc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: caID})
	require.NoError(h.t, err)
	require.Equal(h.t, status, ca.Certificate.Status, "status of CA %s", caID)
	if status == models.StatusRevoked {
		require.Equal(h.t, reason, ca.Certificate.RevocationReason, "revocation reason of CA %s", caID)
	}
}

func (h holdHierarchy) requireCert(serial string, status models.CertificateStatus, reason models.RevocationReason) {
	h.t.Helper()
	cert, err := h.caSvc.GetCertificateBySerialNumber(context.Background(), services.GetCertificatesBySerialNumberInput{SerialNumber: serial})
	require.NoError(h.t, err)
	require.Equal(h.t, status, cert.Status, "status of certificate %s", serial)
	if status == models.StatusRevoked {
		require.Equal(h.t, reason, cert.RevocationReason, "revocation reason of certificate %s", serial)
	}
}

const hold = models.RevocationReason(ocsp.CertificateHold)

// Holding a CA holds its sub-CAs and every certificate below it, instead of revoking them for good.
func TestHoldingACAHoldsWhatItIssued(t *testing.T) {
	h := newHoldHierarchy(t)

	h.setCAStatus(h.root.ID, models.StatusRevoked, hold)

	h.requireCA(h.root.ID, models.StatusRevoked, hold)
	h.requireCA(h.sub.ID, models.StatusRevoked, hold)
	h.requireCert(h.rootCert, models.StatusRevoked, hold)
	h.requireCert(h.subCert, models.StatusRevoked, hold)
}

// Releasing a CA releases what its hold held. The certificate of a root is issued by the root itself: the cascade
// leaves it, so its hold is not overwritten and the root can be released.
func TestReleasingACAReleasesWhatItsHoldHeld(t *testing.T) {
	h := newHoldHierarchy(t)
	h.setCAStatus(h.root.ID, models.StatusRevoked, hold)

	h.setCAStatus(h.root.ID, models.StatusActive, 0)

	h.requireCA(h.root.ID, models.StatusActive, 0)
	h.requireCA(h.sub.ID, models.StatusActive, 0)
	h.requireCert(h.rootCert, models.StatusActive, 0)
	h.requireCert(h.subCert, models.StatusActive, 0)
}

// A certificate on hold before the hold of its CA stays on hold when the CA is released.
func TestReleasingACALeavesWhatWasHeldBefore(t *testing.T) {
	h := newHoldHierarchy(t)
	h.setCertStatus(h.subCert, models.StatusRevoked, hold)
	h.setCAStatus(h.root.ID, models.StatusRevoked, hold)

	h.setCAStatus(h.root.ID, models.StatusActive, 0)

	h.requireCert(h.subCert, models.StatusRevoked, hold)
	h.requireCert(h.rootCert, models.StatusActive, 0)
}

// A certificate held again by hand while its CA is on hold is no longer held by the CA: releasing the CA leaves it.
func TestReleasingACALeavesWhatWasHeldAgainByHand(t *testing.T) {
	h := newHoldHierarchy(t)
	h.setCAStatus(h.root.ID, models.StatusRevoked, hold)
	h.setCertStatus(h.rootCert, models.StatusRevoked, hold)

	h.setCAStatus(h.root.ID, models.StatusActive, 0)

	h.requireCert(h.rootCert, models.StatusRevoked, hold)
}

// A CA that leaves its hold for any status but a revocation releases what its hold held: nothing else could.
func TestExpiringAHeldCAReleasesWhatItsHoldHeld(t *testing.T) {
	h := newHoldHierarchy(t)
	h.setCAStatus(h.root.ID, models.StatusRevoked, hold)

	h.setCAStatus(h.root.ID, models.StatusExpired, 0)

	h.requireCA(h.sub.ID, models.StatusActive, 0)
	h.requireCert(h.rootCert, models.StatusActive, 0)
	h.requireCert(h.subCert, models.StatusActive, 0)
}

// Revoking a CA on hold for good revokes for good what its hold held.
func TestRevokingAHeldCARevokesWhatItsHoldHeld(t *testing.T) {
	h := newHoldHierarchy(t)
	h.setCAStatus(h.root.ID, models.StatusRevoked, hold)

	h.setCAStatus(h.root.ID, models.StatusRevoked, models.RevocationReason(ocsp.KeyCompromise))

	cessation := models.RevocationReason(ocsp.CessationOfOperation)
	h.requireCA(h.root.ID, models.StatusRevoked, models.RevocationReason(ocsp.KeyCompromise))
	h.requireCA(h.sub.ID, models.StatusRevoked, cessation)
	h.requireCert(h.rootCert, models.StatusRevoked, cessation)
	h.requireCert(h.subCert, models.StatusRevoked, cessation)
}
