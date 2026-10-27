package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

func keyURI(cert *models.Certificate) string {
	return "pkcs11:token-id=" + cert.EngineID + ";id=" + cert.KeyID + ";type=private"
}

// boundSerials lists the certificates the KMS records as using the certificate's key.
func boundSerials(t *testing.T, cert *models.Certificate) []string {
	t.Helper()
	require.NotEmpty(t, cert.KeyID, "certificate %s has no KMS key", cert.SerialNumber)
	bindings, err := serverTest.KMS.Service.GetKeyBindings(context.Background(), services.GetKeyInput{Identifier: keyURI(cert)})
	require.NoError(t, err)
	serials := []string{}
	for _, b := range bindings {
		require.Equal(t, models.KMSBindResourceTypeCertificate, b.ResourceType)
		serials = append(serials, b.ResourceID)
	}
	return serials
}

func newBindingsProfile(t *testing.T) *models.IssuanceProfile {
	t.Helper()
	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)
	return profile
}

func createBindingsCA(t *testing.T, cn, profileID, reuseKey string) *models.CACertificate {
	t.Helper()
	ca, err := serverTest.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256, KeyID: reuseKey},
		Subject:      models.Subject{CommonName: cn},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profileID,
	})
	require.NoError(t, err)
	return ca
}

func TestCertificatesAreBoundToTheirKMSKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newBindingsProfile(t)

	t.Run("CA created with a generated key", func(t *testing.T) {
		ca := createBindingsCA(t, "bindings-created", profile.ID, "")
		require.Equal(t, []string{ca.Certificate.SerialNumber}, boundSerials(t, &ca.Certificate))
	})

	t.Run("CA imported with its key", func(t *testing.T) {
		cert, key := selfSignedCAWithForeignSKI(t, "bindings-imported-with-key")
		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)
		require.Equal(t, []string{ca.Certificate.SerialNumber}, boundSerials(t, &ca.Certificate))
	})

	t.Run("CA imported without key, linked to the key the KMS holds", func(t *testing.T) {
		cert, key := selfSignedCAWithForeignSKI(t, "bindings-imported-without-key")
		importKeyInto(t, key, defaultEngine)
		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)
		require.Equal(t, []string{ca.Certificate.SerialNumber}, boundSerials(t, &ca.Certificate))
	})

	issuer := createBindingsCA(t, "bindings-issuer", profile.ID, "")

	t.Run("certificate issued with a generated key", func(t *testing.T) {
		cert, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
			CAID: issuer.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "bindings-generated-leaf"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{cert.SerialNumber}, boundSerials(t, cert))
	})

	t.Run("certificate signed for a key the KMS holds", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		importKeyInto(t, key, defaultEngine)
		csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "bindings-signed-leaf"}, key)
		require.NoError(t, err)
		cert, err := caSvc.SignCertificate(ctx, services.SignCertificateInput{CAID: issuer.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID})
		require.NoError(t, err)
		require.Equal(t, []string{cert.SerialNumber}, boundSerials(t, cert))
	})

	t.Run("a revoked certificate keeps its key", func(t *testing.T) {
		cert, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
			CAID: issuer.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "bindings-revoked-leaf"},
		})
		require.NoError(t, err)
		_, err = caSvc.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{SerialNumber: cert.SerialNumber, NewStatus: models.StatusRevoked, RevocationReason: models.RevocationReason(1)})
		require.NoError(t, err)
		require.Equal(t, []string{cert.SerialNumber}, boundSerials(t, cert))
	})
}

func TestReissuedCAMovesItsKeyBinding(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	profile := newBindingsProfile(t)
	ca := createBindingsCA(t, "bindings-reissue", profile.ID, "")

	reissued, err := serverTest.CA.Service.ReissueCA(context.Background(), services.ReissueCAInput{CAID: ca.ID})
	require.NoError(t, err)
	require.NotEqual(t, ca.Certificate.SerialNumber, reissued.Certificate.SerialNumber)

	require.Equal(t, []string{reissued.Certificate.SerialNumber}, boundSerials(t, &reissued.Certificate))
}

func TestDeletingACAKeepsAKeyStillInUse(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newBindingsProfile(t)

	first := createBindingsCA(t, "bindings-shared-1", profile.ID, "")
	second := createBindingsCA(t, "bindings-shared-2", profile.ID, keyURI(&first.Certificate))
	require.ElementsMatch(t, []string{first.Certificate.SerialNumber, second.Certificate.SerialNumber}, boundSerials(t, &first.Certificate))

	revokeCA(t, caSvc, first.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: first.ID}))

	require.Equal(t, []string{second.Certificate.SerialNumber}, boundSerials(t, &second.Certificate))
	_, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
		CAID: second.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "bindings-after-delete"},
	})
	require.NoError(t, err, "the CA sharing the key must still sign")

	revokeCA(t, caSvc, second.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: second.ID}))
	_, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&second.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound, "the key of the last CA using it is deleted with it")
}

func TestDeletingAnImportedCADeletesItsKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newBindingsProfile(t)

	cert, key := selfSignedCAWithForeignSKI(t, "bindings-delete-imported")
	ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
	require.NoError(t, err)

	revokeCA(t, caSvc, ca.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))

	_, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&ca.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound)
}

func TestDeletingACertificateUnbindsItsKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newBindingsProfile(t)
	issuer := createBindingsCA(t, "bindings-delete-leaf-issuer", profile.ID, "")

	leaf, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
		CAID: issuer.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "bindings-deleted-leaf"},
	})
	require.NoError(t, err)

	// A certificate can only be deleted once its issuer is gone.
	revokeCA(t, caSvc, issuer.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: issuer.ID}))
	require.NoError(t, caSvc.DeleteCertificate(ctx, services.DeleteCertificateInput{SerialNumber: leaf.SerialNumber}))

	require.Empty(t, boundSerials(t, leaf))
}
