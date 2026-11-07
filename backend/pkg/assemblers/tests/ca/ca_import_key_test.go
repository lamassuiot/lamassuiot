package ca

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

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// The test server's default crypto engine is filesystem-1; vault-1 is the other one.
const defaultEngine, otherEngine = "filesystem-1", "vault-1"

func importKeyInto(t *testing.T, key *ecdsa.PrivateKey, engineIDs ...string) {
	t.Helper()
	for _, engineID := range engineIDs {
		_, err := serverTest.KMS.Service.ImportKey(context.Background(), services.ImportKeyInput{PrivateKey: key, EngineID: engineID, Name: "import-key-test"})
		require.NoError(t, err)
	}
}

func TestImportCAWithKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK

	profile, err := caSDK.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)

	t.Run("a key that does not match the certificate is rejected before reaching the KMS", func(t *testing.T) {
		cert, _ := selfSignedCAWithForeignSKI(t, "import-mismatched-key")
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, err = caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: wrongKey, CACertificate: (*models.X509Certificate)(cert)})
		require.ErrorIs(t, err, errs.ErrCAValidCertAndPrivKey)

		orphans, err := serverTest.KMS.Service.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: &wrongKey.PublicKey})
		require.NoError(t, err)
		require.Empty(t, orphans, "a rejected import must not leave its key in the KMS")
	})

	t.Run("the key is imported into the requested engine", func(t *testing.T) {
		cert, key := selfSignedCAWithForeignSKI(t, "import-key-requested-engine")

		ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert), EngineID: otherEngine})
		require.NoError(t, err)
		require.Equal(t, otherEngine, ca.Certificate.EngineID)

		keys, err := serverTest.KMS.Service.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: &key.PublicKey})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{otherEngine}, engineIDsOf(keys))
	})

	t.Run("a copy of the key in another engine does not stop the import", func(t *testing.T) {
		cert, key := selfSignedCAWithForeignSKI(t, "import-key-copy-elsewhere")
		importKeyInto(t, key, otherEngine)

		ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert), EngineID: defaultEngine})
		require.NoError(t, err)
		require.Equal(t, defaultEngine, ca.Certificate.EngineID)
		require.Equal(t, kmsKeyIDOf(t, &key.PublicKey), ca.Certificate.KeyID)
	})
}

// ImportCA must refuse a certificate that is not a CA (basicConstraints CA:FALSE or absent), and must do so
// before its private key reaches the KMS.
func TestImportCARejectsNonCACertificates(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)

	selfSignedLeaf := func(t *testing.T, template *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template.SerialNumber = big.NewInt(time.Now().UnixNano())
		template.NotBefore = time.Now().Add(-time.Hour)
		template.NotAfter = time.Now().Add(24 * time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, key
	}

	cases := map[string]*x509.Certificate{
		"basicConstraints CA:FALSE":  {Subject: pkix.Name{CommonName: "not-ca-false"}, BasicConstraintsValid: true, IsCA: false, KeyUsage: x509.KeyUsageDigitalSignature},
		"no basicConstraints at all": {Subject: pkix.Name{CommonName: "not-ca-absent"}, KeyUsage: x509.KeyUsageDigitalSignature},
	}
	for name, template := range cases {
		t.Run(name, func(t *testing.T) {
			cert, key := selfSignedLeaf(t, template)

			_, err := caSvc.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
			require.ErrorIs(t, err, errs.ErrCANotCA)

			orphans, err := serverTest.KMS.Service.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: &key.PublicKey})
			require.NoError(t, err)
			require.Empty(t, orphans, "a rejected import must not leave its key in the KMS")

			_, err = caSvc.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert)})
			require.ErrorIs(t, err, errs.ErrCANotCA)
		})
	}
}

func engineIDsOf(keys []*models.Key) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.EngineID)
	}
	return ids
}

func TestImportCAWithoutKeyFindsItsKeyByPublicKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK

	for _, tc := range []struct {
		name            string
		heldBy          []string
		requestedEngine string
		wantEngine      string // empty: imported without key
	}{
		{name: "held by the requested engine", heldBy: []string{otherEngine}, requestedEngine: otherEngine, wantEngine: otherEngine},
		{name: "requested engine preferred over the default", heldBy: []string{defaultEngine, otherEngine}, requestedEngine: otherEngine, wantEngine: otherEngine},
		{name: "default engine preferred when none is requested", heldBy: []string{defaultEngine, otherEngine}, wantEngine: defaultEngine},
		{name: "default engine used when the requested one does not hold it", heldBy: []string{defaultEngine}, requestedEngine: otherEngine, wantEngine: defaultEngine},
		{name: "any engine holding it when the default does not", heldBy: []string{otherEngine}, wantEngine: otherEngine},
		{name: "held by no engine", wantEngine: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := selfSignedCAWithForeignSKI(t, "import-without-key "+tc.name)
			importKeyInto(t, key, tc.heldBy...)

			ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert), EngineID: tc.requestedEngine})
			require.NoError(t, err)

			require.Equal(t, tc.wantEngine, ca.Certificate.EngineID)
			if tc.wantEngine == "" {
				require.Equal(t, models.CertificateTypeImportedWithoutKey, ca.Certificate.Type)
				require.Empty(t, ca.Certificate.KeyID)
				return
			}
			require.Equal(t, models.CertificateTypeManaged, ca.Certificate.Type)
			require.Equal(t, kmsKeyIDOf(t, &key.PublicKey), ca.Certificate.KeyID)
		})
	}
}

func TestSignCertificateLinksAKeyHeldBySeveralEngines(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK

	profile, err := caSDK.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)
	issuer, err := caSDK.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: "sign-multi-engine-issuer"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
	})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	importKeyInto(t, key, defaultEngine, otherEngine)
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "sign-multi-engine-leaf"}, key)
	require.NoError(t, err)

	cert, err := caSDK.SignCertificate(ctx, services.SignCertificateInput{
		CAID: issuer.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID,
	})
	require.NoError(t, err)
	require.Equal(t, models.CertificateTypeManaged, cert.Type)
	require.Equal(t, defaultEngine, cert.EngineID)
	require.Equal(t, kmsKeyIDOf(t, &key.PublicKey), cert.KeyID)
}

// subCAIssuedOutsideLamassu returns an intermediate CA certificate whose issuer is not in Lamassu.
func subCAIssuedOutsideLamassu(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	root, rootKey := selfSignedCAWithForeignSKI(t, cn+" outside root")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// A second CA on the same certificate row would share its status and key: revoking or deleting it, for
// example to clean up a retried import, would revoke the first CA and delete its key.
func TestImportingTheCertificateOfAnExistingCAIsRejected(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK
	profile := newKeyRefsProfile(t)

	cert, key := selfSignedCAWithForeignSKI(t, "import-existing-ca")
	existing, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
	require.NoError(t, err)

	t.Run("without key", func(t *testing.T) {
		_, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, CACertificate: (*models.X509Certificate)(cert)})
		require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
	})

	t.Run("with its key", func(t *testing.T) {
		_, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
		require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
	})

	var ids []string
	_, err = caSDK.GetCAsByCommonName(ctx, services.GetCAsByCommonNameInput{CommonName: "import-existing-ca", ExhaustiveRun: true, ApplyFunc: func(ca models.CACertificate) { ids = append(ids, ca.ID) }})
	require.NoError(t, err)
	require.Equal(t, []string{existing.ID}, ids)
	stored, err := caSDK.GetCAByID(ctx, services.GetCAByIDInput{CAID: existing.ID})
	require.NoError(t, err)
	require.Equal(t, models.StatusActive, stored.Certificate.Status)
	require.Equal(t, existing.Certificate.KeyID, stored.Certificate.KeyID)
}

// DeleteCA keeps the certificate row (#815), and ImportCA reuses it when the same certificate is imported again.
// The reused row must reference the key this import brings, or the CA comes back without one. The CA is an
// intermediate because DeleteCA revokes the row of a self-signed CA, which is then reimported revoked.
func TestReimportingADeletedKeylessCALinksTheKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	profile := newKeyRefsProfile(t)

	importKeylessAndDelete := func(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
		t.Helper()
		cert, key := subCAIssuedOutsideLamassu(t, cn)
		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)
		require.Empty(t, ca.Certificate.KeyID)
		require.NoError(t, caSvc.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))
		return cert, key
	}

	requireSigns := func(t *testing.T, ca *models.CACertificate, cn string) {
		t.Helper()
		_, err := caSvc.CreateCertificate(ctx, services.CreateCertificateInput{
			CAID: ca.ID, KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256}, Subject: models.Subject{CommonName: cn},
		})
		require.NoError(t, err)
	}

	t.Run("with its private key", func(t *testing.T) {
		cert, key := importKeylessAndDelete(t, "reimport-with-key")

		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)

		require.Equal(t, models.CertificateTypeImportedWithKey, ca.Certificate.Type)
		require.Equal(t, kmsKeyIDOf(t, &key.PublicKey), ca.Certificate.KeyID)
		require.Equal(t, ca.Certificate.KeyID, storedKeyID(t, ca.Certificate.SerialNumber))
		requireKeyInUse(t, &ca.Certificate)
		requireSigns(t, ca, "reimport-with-key-leaf")
	})

	t.Run("without key, once the KMS holds it", func(t *testing.T) {
		cert, key := importKeylessAndDelete(t, "reimport-key-in-kms")
		importKeyInto(t, key, defaultEngine)

		ca, err := caSvc.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)

		require.Equal(t, models.CertificateTypeManaged, ca.Certificate.Type)
		require.Equal(t, defaultEngine, ca.Certificate.EngineID)
		require.Equal(t, kmsKeyIDOf(t, &key.PublicKey), ca.Certificate.KeyID)
		requireSigns(t, ca, "reimport-key-in-kms-leaf")
	})
}
