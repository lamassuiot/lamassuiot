package cryptoengines

import (
	"cloudflare/circl/sign/mldsa/mldsa65"
	"crypto"
	"crypto/ed25519"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func SharedTestCreateRSAPrivateKey(t *testing.T, engine CryptoEngine) {
	keyID, signer, err := engine.CreateRSAPrivateKey(2048)
	assert.NoError(t, err)
	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestCreateECDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	keyID, signer, err := engine.CreateECDSAPrivateKey(elliptic.P256())
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestCreateMLDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	keyID, signer, err := engine.CreateMLDSAPrivateKey(44)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestCreateEd25519PrivateKey(t *testing.T, engine CryptoEngine) {
	keyID, signer, err := engine.CreateEd25519PrivateKey()
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestDeleteKey(t *testing.T, engine CryptoEngine) {
	keyID, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
	assert.NoError(t, err)

	_, err = engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	err = engine.DeleteKey(keyID)
	assert.NoError(t, err)
}

func SharedGetKey(t *testing.T, engine CryptoEngine) {
	keyID, key, err := engine.CreateECDSAPrivateKey(elliptic.P256())
	assert.NoError(t, err)

	signer, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	assert.Equal(t, key, signer)
}

func SharedListKeys(t *testing.T, engine CryptoEngine) {
	keys, err := engine.ListPrivateKeyIDs()
	assert.NoError(t, err)
	assert.Len(t, keys, 0)

	keyID1, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
	assert.NoError(t, err)

	keyID2, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
	assert.NoError(t, err)

	keys, err = engine.ListPrivateKeyIDs()
	assert.NoError(t, err)

	assert.Contains(t, keys, keyID1)
	assert.Contains(t, keys, keyID2)

	assert.Len(t, keys, 2)
}

func SharedRenameKey(t *testing.T, engine CryptoEngine) {
	keyID, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
	assert.NoError(t, err)

	err = engine.RenameKey(keyID, "new-key-id")
	assert.NoError(t, err)

	_, err = engine.GetPrivateKeyByID(keyID)
	assert.Error(t, err)

	signer, err := engine.GetPrivateKeyByID("new-key-id")
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

func SharedGetKeyNotFound(t *testing.T, engine CryptoEngine) {
	_, err := engine.GetPrivateKeyByID("non-existing-key")
	assert.Error(t, err)
}

func SharedTestRSAPSSSignature(t *testing.T, engine CryptoEngine) {
	keyID, signer, err := engine.CreateRSAPrivateKey(2048)
	assert.NoError(t, err)

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

	// Test RSA_PSS signature
	signature, err := signer.Sign(rand.Reader, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	err = rsa.VerifyPSS(signer2.Public().(*rsa.PublicKey), crypto.SHA256, hashed, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, //EqualsHash is used by x509 package to sign certificates
		Hash:       crypto.SHA256,
	})

	assert.NoError(t, err)
}

func SharedTestRSAPKCS1v15Signature(t *testing.T, engine CryptoEngine) {
	keyID, signer, err := engine.CreateRSAPrivateKey(2048)
	assert.NoError(t, err)

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

	// Test PKCS1v15 signature
	signature, err := signer.Sign(rand.Reader, hashed, crypto.SHA256)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	err = rsa.VerifyPKCS1v15(signer2.Public().(*rsa.PublicKey), crypto.SHA256, hashed, signature)
	assert.NoError(t, err)
}

func SharedTestECDSASignature(t *testing.T, engine CryptoEngine) {
	keyID, signer, err := engine.CreateECDSAPrivateKey(elliptic.P256())
	assert.NoError(t, err)

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

	signature, err := signer.Sign(rand.Reader, hashed, crypto.SHA256)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	res := ecdsa.VerifyASN1(signer2.Public().(*ecdsa.PublicKey), hashed, signature)
	assert.True(t, res)
}

func SharedTestMLDSASignature(t *testing.T, engine CryptoEngine) {
	keyID, signer, err := engine.CreateMLDSAPrivateKey(65)
	assert.NoError(t, err)

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

	signature, err := signer.Sign(rand.Reader, hashed, crypto.Hash(0))
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	res := mldsa65.Verify(signer2.Public().(*mldsa65.PublicKey), hashed, nil, signature)
	assert.True(t, res)
}

func SharedTestImportRSAPrivateKey(t *testing.T, engine CryptoEngine) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	assert.NoError(t, err)

	pubKey := key.Public().(*rsa.PublicKey)

	_, importedSigner, err := engine.ImportRSAPrivateKey(key)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(*rsa.PublicKey)
	assert.Equal(t, pubKey.N, importedPubKey.N)
	assert.Equal(t, pubKey.E, importedPubKey.E)
}

func SharedTestImportECDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.NoError(t, err)

	pubKey := key.Public().(*ecdsa.PublicKey)

	_, importedSigner, err := engine.ImportECDSAPrivateKey(key)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(*ecdsa.PublicKey)
	assert.Equal(t, pubKey.X, importedPubKey.X)
	assert.Equal(t, pubKey.Y, importedPubKey.Y)
}

func SharedTestImportMLDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	_, key, err := mldsa65.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pubKey := key.Public().(*mldsa65.PublicKey)

	_, importedSigner, err := engine.ImportMLDSAPrivateKey(key)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(*mldsa65.PublicKey)
	assert.Equal(t, pubKey.A, importedPubKey.A)
}

func SharedTestImportEd25519PrivateKey(t *testing.T, engine CryptoEngine) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pubKey := key.Public().(ed25519.PublicKey)

	_, importedSigner, err := engine.ImportEd25519PrivateKey(key)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(ed25519.PublicKey)
	assert.Equal(t, pubKey, importedPubKey)
}
