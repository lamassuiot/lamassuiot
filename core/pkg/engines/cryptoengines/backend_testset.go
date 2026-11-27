package cryptoengines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/kmip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BackendTest is one test every Backend implementation must pass.
type BackendTest struct {
	Name string
	Fn   func(t *testing.T, b Backend)
}

// SharedBackendTests returns the tests every Backend must pass. Engine test suites run them on their engine,
// natively or wrapped by the legacy adapter.
func SharedBackendTests() []BackendTest {
	return []BackendTest{
		{"GenerateRSA2048", backendTestGenerate(kmip.RSA, 2048)},
		{"GenerateECDSAP256", backendTestGenerate(kmip.ECDSA, 256)},
		{"ImportECDSAP256", backendTestImportECDSA},
		{"LoadAndSignRSA", backendTestLoadAndSignRSA},
		{"LoadAndSignECDSA", backendTestLoadAndSignECDSA},
		{"Destroy", backendTestDestroy},
		{"LoadUnknown", backendTestLoadUnknown},
		{"CapabilitiesListSigningKeys", backendTestCapabilities},
	}
}

func publicKeyDigest(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}

func generateSigner(t *testing.T, b Backend, alg kmip.CryptographicAlgorithm, length int) Signer {
	t.Helper()
	h, err := b.Generate(context.Background(), GenerateSpec{ObjectType: kmip.PrivateKey, Algorithm: alg, Length: length})
	require.NoError(t, err)
	signer, ok := h.(Signer)
	require.True(t, ok, "a private key handle must be a Signer")
	return signer
}

// A generated key without a chosen KeyID is named after the SHA-256 of its public key.
func backendTestGenerate(alg kmip.CryptographicAlgorithm, length int) func(t *testing.T, b Backend) {
	return func(t *testing.T, b Backend) {
		signer := generateSigner(t, b, alg, length)
		assert.Equal(t, KeyRef{KeyID: publicKeyDigest(t, signer.Public()), ObjectType: kmip.PrivateKey, Algorithm: alg, Length: length}, signer.Ref())

		loaded, err := b.Load(context.Background(), signer.Ref())
		require.NoError(t, err)
		assert.Equal(t, signer.Public(), loaded.(Signer).Public())
	}
}

func backendTestImportECDSA(t *testing.T, b Backend) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	h, err := b.Import(context.Background(), ImportSpec{ObjectType: kmip.PrivateKey, Private: key})
	require.NoError(t, err)
	assert.Equal(t, KeyRef{KeyID: publicKeyDigest(t, &key.PublicKey), ObjectType: kmip.PrivateKey, Algorithm: kmip.ECDSA, Length: 256}, h.Ref())
	assert.True(t, key.PublicKey.Equal(h.(Signer).Public()))
}

func backendTestLoadAndSignRSA(t *testing.T, b Backend) {
	created := generateSigner(t, b, kmip.RSA, 2048)
	h, err := b.Load(context.Background(), created.Ref())
	require.NoError(t, err)
	signer, ok := h.(Signer)
	require.True(t, ok)

	digest := sha256.Sum256([]byte("lamassu"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(created.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig))
}

func backendTestLoadAndSignECDSA(t *testing.T, b Backend) {
	created := generateSigner(t, b, kmip.ECDSA, 256)
	h, err := b.Load(context.Background(), created.Ref())
	require.NoError(t, err)
	signer, ok := h.(Signer)
	require.True(t, ok)

	digest := sha256.Sum256([]byte("lamassu"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(created.Public().(*ecdsa.PublicKey), digest[:], sig))
}

func backendTestDestroy(t *testing.T, b Backend) {
	created := generateSigner(t, b, kmip.ECDSA, 256)
	require.NoError(t, b.Destroy(context.Background(), created.Ref()))

	_, err := b.Load(context.Background(), created.Ref())
	assert.Error(t, err)
}

func backendTestLoadUnknown(t *testing.T, b Backend) {
	_, err := b.Load(context.Background(), KeyRef{KeyID: "0000000000000000000000000000000000000000000000000000000000000000", ObjectType: kmip.PrivateKey, Algorithm: kmip.ECDSA, Length: 256})
	assert.Error(t, err)
}

// Every engine creates and signs with at least RSA 2048 or ECDSA P-256 keys, and says so.
func backendTestCapabilities(t *testing.T, b Backend) {
	caps := b.Capabilities()
	assert.True(t, caps.Supports(kmip.OpCreateKeyPair, kmip.RSA, 2048) || caps.Supports(kmip.OpCreateKeyPair, kmip.ECDSA, 256))
	for _, item := range caps.Items {
		if item.Operation != kmip.OpCreateKeyPair {
			continue
		}
		for _, length := range item.Lengths {
			assert.True(t, caps.Supports(kmip.OpSign, item.Algorithm, length), "%s %d can be created but not used to sign", item.Algorithm, length)
		}
	}
}
