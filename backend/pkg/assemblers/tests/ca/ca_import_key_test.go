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
