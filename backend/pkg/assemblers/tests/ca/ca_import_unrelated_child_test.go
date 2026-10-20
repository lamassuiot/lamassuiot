package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Importing a CA looks for existing CAs it issued, matching their issuer and AKI. A CA that matches
// but was not signed by the imported one is skipped, and must not turn the import into an error.
func TestImportCAWithUnrelatedCandidateChild(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caTest := serverTest.CA

	profile, err := caTest.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)

	// Two roots with the same subject and SKI but different keys.
	ski := []byte{0x01, 0x02, 0x03, 0x04}
	newRoot := func() (*x509.Certificate, *rsa.PrivateKey) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "Shared Root"},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			SubjectKeyId:          ski,
			AuthorityKeyId:        ski,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, key
	}

	firstCert, firstKey := newRoot()
	first, err := caTest.Service.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(firstCert), Key: firstKey, ProfileID: profile.ID})
	require.NoError(t, err)

	// A CA issued by the first root, so its issuer and AKI also match the second one.
	child, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
		ParentID:     first.ID,
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "Child"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
		ProfileID:    profile.ID,
	})
	require.NoError(t, err)

	secondCert, _ := newRoot()
	second, err := caTest.Service.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(secondCert), ProfileID: profile.ID})
	require.NoError(t, err, "the second root was imported")
	require.NotNil(t, second)

	stored, err := caTest.Service.GetCAByID(ctx, services.GetCAByIDInput{CAID: child.ID})
	require.NoError(t, err)
	assert.Equal(t, first.ID, stored.Certificate.IssuerCAMetadata.ID, "the child keeps its actual issuer")
}
