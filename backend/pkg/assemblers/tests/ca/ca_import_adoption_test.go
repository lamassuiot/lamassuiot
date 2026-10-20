package ca

import (
	"context"
	"crypto"
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

// issueTestCA issues a CA certificate for pub, signed by parent (self-signed when parent is nil).
func issueTestCA(t *testing.T, cn string, ski, aki []byte, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski,
		AuthorityKeyId:        aki,
	}
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// Importing a CA adopts the CAs it issued that were imported before it, and only those.
func TestImportCAAdoptsOnlyOrphanChildren(t *testing.T) {
	ctx := context.Background()
	caTest := serverTest.CA

	newProfile := func(t *testing.T) string {
		require.NoError(t, serverTest.BeforeEach())
		profile, err := caTest.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
		})
		require.NoError(t, err)
		return profile.ID
	}
	importCA := func(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey, profileID string) *models.CACertificate {
		t.Helper()
		input := services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert), ProfileID: profileID}
		if key != nil {
			input.Key = key
		}
		ca, err := caTest.Service.ImportCA(ctx, input)
		require.NoError(t, err)
		return ca
	}
	parentOf := func(t *testing.T, caID string) (string, int) {
		t.Helper()
		ca, err := caTest.Service.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
		require.NoError(t, err)
		return ca.Certificate.IssuerCAMetadata.ID, ca.Level
	}

	t.Run("CrossCertificateKeepsSubordinates", func(t *testing.T) {
		profileID := newProfile(t)

		aKey := newTestRSAKey(t)
		aSKI := []byte{0xa1}
		aCert := issueTestCA(t, "Cross A", aSKI, aSKI, &aKey.PublicKey, nil, aKey)
		a := importCA(t, aCert, aKey, profileID)

		b, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
			ParentID:     a.ID,
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: "Cross B"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
			ProfileID:    profileID,
		})
		require.NoError(t, err)

		// A cross certificate for A: same subject, SKI and key, issued by another root.
		otherKey := newTestRSAKey(t)
		otherRoot := issueTestCA(t, "Other Root", []byte{0xb1}, []byte{0xb1}, &otherKey.PublicKey, nil, otherKey)
		crossA := issueTestCA(t, "Cross A", aSKI, []byte{0xb1}, &aKey.PublicKey, otherRoot, otherKey)
		importCA(t, crossA, nil, profileID)

		parentID, level := parentOf(t, b.ID)
		assert.Equal(t, a.ID, parentID, "the subordinate keeps its parent")
		assert.Equal(t, 1, level)
	})

	t.Run("OrphansAreAdopted", func(t *testing.T) {
		profileID := newProfile(t)

		rKey, cKey, dKey := newTestRSAKey(t), newTestRSAKey(t), newTestRSAKey(t)
		rCert := issueTestCA(t, "Orphan R", []byte{0xc1}, []byte{0xc1}, &rKey.PublicKey, nil, rKey)
		cCert := issueTestCA(t, "Orphan C", []byte{0xc2}, []byte{0xc1}, &cKey.PublicKey, rCert, rKey)
		dCert := issueTestCA(t, "Orphan D", []byte{0xc3}, []byte{0xc2}, &dKey.PublicKey, cCert, cKey)

		// C and D are imported before R, so C is stored without parent.
		c := importCA(t, cCert, nil, profileID)
		d := importCA(t, dCert, nil, profileID)
		parentID, _ := parentOf(t, d.ID)
		require.Equal(t, c.ID, parentID)

		r := importCA(t, rCert, rKey, profileID)

		parentID, level := parentOf(t, c.ID)
		assert.Equal(t, r.ID, parentID)
		assert.Equal(t, 1, level)
		parentID, level = parentOf(t, d.ID)
		assert.Equal(t, c.ID, parentID)
		assert.Equal(t, 2, level, "the levels of the adopted CA's descendants are updated")
	})
}
