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

// requireKeyInUse checks the certificate references a key of the KMS and that the KMS refuses to delete
// it for that reason.
func requireKeyInUse(t *testing.T, cert *models.Certificate) {
	t.Helper()
	require.NotEmpty(t, cert.KeyID, "certificate %s has no KMS key", cert.SerialNumber)
	err := serverTest.KMS.Service.DeleteKeyByID(context.Background(), services.GetKeyInput{Identifier: keyURI(cert)})
	require.ErrorIs(t, err, errs.ErrKeyInUse)
}

// storedKeyID is the key the CA has stored for a certificate: empty when it references none.
func storedKeyID(t *testing.T, serial string) string {
	t.Helper()
	cert, err := serverTest.CA.Service.GetCertificateBySerialNumber(context.Background(), services.GetCertificatesBySerialNumberInput{SerialNumber: serial})
	require.NoError(t, err)
	return cert.KeyID
}

func newKeyRefsProfile(t *testing.T) *models.IssuanceProfile {
	t.Helper()
	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)
	return profile
}

func createKeyRefsCA(t *testing.T, cn, profileID, reuseKey string) *models.CACertificate {
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

func reissueCA(t *testing.T, caID string) *models.CACertificate {
	t.Helper()
	reissued, err := serverTest.CA.Service.ReissueCA(context.Background(), services.ReissueCAInput{CAID: caID})
	require.NoError(t, err)
	return reissued
}

func TestKeyOfACertificateCannotBeDeleted(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)

	t.Run("CA created with a generated key", func(t *testing.T) {
		ca := createKeyRefsCA(t, "references-created", profile.ID, "")
		requireKeyInUse(t, &ca.Certificate)
	})

	t.Run("CA imported with its key", func(t *testing.T) {
		cert, key := selfSignedCAWithForeignSKI(t, "references-imported-with-key")
		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)
		requireKeyInUse(t, &ca.Certificate)
	})

	t.Run("CA imported without key, linked to the key the KMS holds", func(t *testing.T) {
		cert, key := selfSignedCAWithForeignSKI(t, "references-imported-without-key")
		importKeyInto(t, key, defaultEngine)
		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)
		requireKeyInUse(t, &ca.Certificate)
	})

	issuer := createKeyRefsCA(t, "references-issuer", profile.ID, "")

	t.Run("certificate issued with a generated key", func(t *testing.T) {
		cert, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
			CAID: issuer.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "references-generated-leaf"},
		})
		require.NoError(t, err)
		requireKeyInUse(t, cert)
	})

	t.Run("certificate signed for a key the KMS holds", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		importKeyInto(t, key, defaultEngine)
		csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "references-signed-leaf"}, key)
		require.NoError(t, err)
		cert, err := caSvc.SignCertificate(ctx, services.SignCertificateInput{CAID: issuer.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID})
		require.NoError(t, err)
		requireKeyInUse(t, cert)
	})

	t.Run("a revoked certificate keeps its key", func(t *testing.T) {
		cert, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
			CAID: issuer.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "references-revoked-leaf"},
		})
		require.NoError(t, err)
		_, err = caSvc.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{SerialNumber: cert.SerialNumber, NewStatus: models.StatusRevoked, RevocationReason: models.RevocationReason(1)})
		require.NoError(t, err)
		requireKeyInUse(t, cert)
	})
}

func TestReissuedCAKeepsItsKeyInUse(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	profile := newKeyRefsProfile(t)
	ca := createKeyRefsCA(t, "references-reissue", profile.ID, "")

	second := reissueCA(t, ca.ID)
	third := reissueCA(t, ca.ID)

	for _, cert := range []*models.CACertificate{ca, second, third} {
		require.Equal(t, ca.Certificate.KeyID, storedKeyID(t, cert.Certificate.SerialNumber), "every certificate of the CA keeps its key")
	}
	requireKeyInUse(t, &third.Certificate)
}

func TestDeletingAReissuedCADeletesItsKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)
	ca := createKeyRefsCA(t, "references-delete-reissued", profile.ID, "")
	second := reissueCA(t, ca.ID)
	third := reissueCA(t, ca.ID)

	revokeCA(t, caSvc, ca.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))

	_, err := serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&third.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound)
	for _, sn := range []string{ca.Certificate.SerialNumber, second.Certificate.SerialNumber, third.Certificate.SerialNumber} {
		require.Empty(t, storedKeyID(t, sn), "the certificates of a deleted CA stay for its issuer's CRL and OCSP, without the key")
	}
}

func TestDeletingAReissuedCAKeepsTheKeyOfACAWithTheSameKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)

	first := createKeyRefsCA(t, "references-shared-reissued-1", profile.ID, "")
	second := createKeyRefsCA(t, "references-shared-reissued-2", profile.ID, keyURI(&first.Certificate))
	firstReissued := reissueCA(t, first.ID)
	secondReissued := reissueCA(t, second.ID)

	revokeCA(t, caSvc, first.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: first.ID}))

	require.Empty(t, storedKeyID(t, first.Certificate.SerialNumber))
	require.Empty(t, storedKeyID(t, firstReissued.Certificate.SerialNumber))
	require.Equal(t, second.Certificate.KeyID, storedKeyID(t, second.Certificate.SerialNumber))
	require.Equal(t, second.Certificate.KeyID, storedKeyID(t, secondReissued.Certificate.SerialNumber))
	requireKeyInUse(t, &secondReissued.Certificate)
}

func TestDeletingACAKeepsAKeyStillInUse(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)

	first := createKeyRefsCA(t, "references-shared-1", profile.ID, "")
	second := createKeyRefsCA(t, "references-shared-2", profile.ID, keyURI(&first.Certificate))
	require.Equal(t, first.Certificate.KeyID, second.Certificate.KeyID)

	revokeCA(t, caSvc, first.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: first.ID}))

	requireKeyInUse(t, &second.Certificate)
	_, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
		CAID: second.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "references-after-delete"},
	})
	require.NoError(t, err, "the CA sharing the key must still sign")

	revokeCA(t, caSvc, second.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: second.ID}))
	_, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&second.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound, "the key of the last CA using it is deleted with it")
}

// The reissue history is certificate metadata a user can edit: pointing it at another CA must not
// release that CA's certificates and delete the key it still uses.
func TestDeletingACAWithAForgedReissueHistoryKeepsAKeyStillInUse(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)

	setMetadata := func(t *testing.T, serial, key, value string) {
		t.Helper()
		_, err := caSvc.UpdateCertificateMetadata(ctx, services.UpdateCertificateMetadataInput{
			SerialNumber: serial,
			Patches:      chelpers.NewPatchBuilder().Add(chelpers.JSONPointerBuilder(key), value).Build(),
		})
		require.NoError(t, err)
	}

	for _, tc := range []struct {
		name     string
		previous func(previous, current string) string
		linkBack bool // also forge the reissued-as link back from the targeted certificate
	}{
		{name: "pointing at the current certificate of another CA", previous: func(_, current string) string { return current }},
		{name: "pointing at a certificate another CA reissued", previous: func(previous, _ string) string { return previous }},
		{name: "linking both ways with the current certificate of another CA", previous: func(_, current string) string { return current }, linkBack: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			victim := createKeyRefsCA(t, "references-forged-victim", profile.ID, "")
			victimPrevious := victim.Certificate.SerialNumber
			victim = reissueCA(t, victim.ID)
			forgedPrevious := tc.previous(victimPrevious, victim.Certificate.SerialNumber)

			forger := createKeyRefsCA(t, "references-forged-forger", profile.ID, keyURI(&victim.Certificate))
			setMetadata(t, forger.Certificate.SerialNumber, models.CAMetadataReissuedFromKey, forgedPrevious)
			if tc.linkBack {
				setMetadata(t, forgedPrevious, models.CAMetadataReissuedAsKey, forger.Certificate.SerialNumber)
			}

			revokeCA(t, caSvc, forger.ID)
			require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: forger.ID}))

			require.Equal(t, victim.Certificate.KeyID, storedKeyID(t, victimPrevious))
			require.Equal(t, victim.Certificate.KeyID, storedKeyID(t, victim.Certificate.SerialNumber))
			requireKeyInUse(t, &victim.Certificate)
			_, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
				CAID: victim.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "references-after-forged-delete"},
			})
			require.NoError(t, err, "the CA whose history was forged still signs")
		})
	}
}

func TestDeletingAnImportedCADeletesItsKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)

	cert, key := selfSignedCAWithForeignSKI(t, "references-delete-imported")
	ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
	require.NoError(t, err)

	revokeCA(t, caSvc, ca.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))

	_, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&ca.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound)
}

func TestDeletingACertificateReleasesItsKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)
	issuer := createKeyRefsCA(t, "references-delete-leaf-issuer", profile.ID, "")

	leaf, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
		CAID: issuer.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: "references-deleted-leaf"},
	})
	require.NoError(t, err)
	requireKeyInUse(t, leaf)

	// A certificate can only be deleted once its issuer is gone.
	revokeCA(t, caSvc, issuer.ID)
	require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: issuer.ID}))
	require.NoError(t, caSvc.DeleteCertificate(ctx, services.DeleteCertificateInput{SerialNumber: leaf.SerialNumber}))

	require.NoError(t, serverTest.KMS.Service.DeleteKeyByID(ctx, services.GetKeyInput{Identifier: keyURI(leaf)}),
		"with its only certificate gone, nothing references the key")
}
