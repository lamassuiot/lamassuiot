package services

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// newHoldFixture holds the active certificate s1, issued by the CA ca-1.
func newHoldFixture(t *testing.T) deleteCAFixture {
	t.Helper()
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.addIssuedCertificate("ca-1", "s1")
	s1 := f.certs.certificates["s1"]
	s1.Certificate = f.cas.cas["ca-1"].Certificate.Certificate
	f.certs.certificates["s1"] = s1
	return f
}

// The hold of a CA marks each certificate in the same write that puts it on hold: no later write can be lost between
// the two and leave the certificate held for good.
func TestUpdateCertificateStatusMarksAHoldByACAInTheSameWrite(t *testing.T) {
	f := newHoldFixture(t)

	held, err := f.svc.UpdateCertificateStatus(context.Background(), coreservices.UpdateCertificateStatusInput{
		SerialNumber: "s1", NewStatus: models.StatusRevoked, RevocationReason: ocsp.CertificateHold, SuspendedByCascadeOf: "ca-1",
	})
	require.NoError(t, err)
	require.Equal(t, "ca-1", held.Metadata[models.CAMetadataSuspendedByCascadeKey])
	require.Equal(t, "ca-1", f.certs.certificates["s1"].Metadata[models.CAMetadataSuspendedByCascadeKey])
}

// Only a hold is marked: a permanent revocation is not released with the CA.
func TestUpdateCertificateStatusDoesNotMarkAPermanentRevocation(t *testing.T) {
	f := newHoldFixture(t)

	_, err := f.svc.UpdateCertificateStatus(context.Background(), coreservices.UpdateCertificateStatusInput{
		SerialNumber: "s1", NewStatus: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise, SuspendedByCascadeOf: "ca-1",
	})
	require.NoError(t, err)
	require.NotContains(t, f.certs.certificates["s1"].Metadata, models.CAMetadataSuspendedByCascadeKey)
}
