package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Clients such as the DMS Manager accept exactly these sources, so the matcher must resolve every one.
func TestX509MatcherResolvesEveryListedAttributeSource(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "device-1"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	for _, source := range models.X509SubjectAttributeSources {
		principal := models.Principal{Type: "x509", AuthConfig: models.AuthConfig{"subject_attribute_mappings": map[string]any{"attr": source}}}
		attrs, err := X509Matcher{}.ResolveSubjectAttributes(principal, cert)
		require.NoError(t, err)
		assert.NotEmpty(t, attrs["attr"], source)
	}
}
