package migrations38to40

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- recomputes the SKI OpenSSL writes (RFC 5280 method 1), not a security use
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/stretchr/testify/require"
)

const (
	engineID  = "filesystem-1"
	skiB      = "706174617461"   // "patata" in ASCII
	skiE      = "70617461746132" // "patata2" in ASCII
	crlDomain = "lamassu.example"
)

// fixtureCA is a CA certificate of testdata/ with its key (see testdata/gen.sh).
type fixtureCA struct {
	Name   string // "A" … "E"
	Cert   *x509.Certificate
	Key    crypto.Signer
	KeyPEM []byte // PKCS#8 PEM: the content of the engine file
	Digest string // hex SHA-256 of the DER SubjectPublicKeyInfo: the name the KMS gives the key
	SKI    string // hex of Cert.SubjectKeyId
}

func loadFixture(t *testing.T, name string) fixtureCA {
	t.Helper()
	base := filepath.Join("testdata", strings.ToLower(name))
	certPEM, err := os.ReadFile(base + ".crt.pem")
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(base + ".key.pem")
	require.NoError(t, err)
	cert, err := chelpers.ParseCertificate(string(certPEM))
	require.NoError(t, err)
	key, err := chelpers.ParsePrivateKey(keyPEM)
	require.NoError(t, err)
	digest, err := chelpers.PublicKeyDigest(cert.PublicKey)
	require.NoError(t, err)
	return fixtureCA{Name: name, Cert: cert, Key: key.(crypto.Signer), KeyPEM: keyPEM, Digest: digest, SKI: hex.EncodeToString(cert.SubjectKeyId)}
}

// opensslSKI is the SKI OpenSSL writes for subjectKeyIdentifier=hash: the SHA-1 of the subjectPublicKey BIT STRING,
// not of the whole SubjectPublicKeyInfo (RFC 5280 4.2.1.2, method 1).
func opensslSKI(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(der, &spki)
	require.NoError(t, err)
	sum := sha1.Sum(spki.PublicKey.Bytes) // #nosec G401 -- see the import
	return hex.EncodeToString(sum[:])
}

// kmsPublicKey is a public key as the KMS stores it: the base64 of its PEM encoding.
func kmsPublicKey(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// certB64PEM is a certificate as ca.certificates stores it: the base64 of its PEM encoding.
func certB64PEM(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// The fixtures are what the scenario is about: SKIs written by OpenSSL, arbitrary ones, and the one Lamassu writes.
func TestFixtures(t *testing.T) {
	a, b, c, d, e := loadFixture(t, "A"), loadFixture(t, "B"), loadFixture(t, "C"), loadFixture(t, "D"), loadFixture(t, "E")

	require.Equal(t, opensslSKI(t, a.Cert.PublicKey), a.SKI)
	require.Equal(t, opensslSKI(t, d.Cert.PublicKey), d.SKI)
	require.Equal(t, skiB, b.SKI)
	require.Equal(t, skiE, e.SKI)
	require.Equal(t, c.Digest, c.SKI)
	require.Equal(t, c.Cert.SubjectKeyId, c.Cert.AuthorityKeyId)
	require.Equal(t, []string{"http://" + crlDomain + "/crl/" + c.Digest}, c.Cert.CRLDistributionPoints)
	require.NotEqual(t, a.SKI, a.Digest, "an OpenSSL SKI is not the digest of the key")

	curves := map[string]elliptic.Curve{"A": elliptic.P256(), "C": elliptic.P256(), "D": elliptic.P384()}
	for _, fx := range []fixtureCA{a, b, c, d, e} {
		require.True(t, fx.Cert.IsCA, fx.Name)
		require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, fx.Cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign), fx.Name)
		require.True(t, fx.Key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(fx.Cert.PublicKey), "%s: key and certificate", fx.Name)
		switch pub := fx.Cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			require.Equal(t, curves[fx.Name], pub.Curve, fx.Name)
		case *rsa.PublicKey:
			require.Contains(t, []string{"B", "E"}, fx.Name)
			require.Equal(t, 2048, pub.N.BitLen(), fx.Name)
		default:
			t.Fatalf("%s: unexpected key type %T", fx.Name, pub)
		}
	}
}
