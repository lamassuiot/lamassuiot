package cryptoengines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func SharedTestCreateRSAPrivateKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateRSAPrivateKey(ctx, 2048)
	assert.NoError(t, err)
	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestCreateECDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateECDSAPrivateKey(ctx, elliptic.P256())
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestDeleteKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, _, err := engine.CreateECDSAPrivateKey(ctx, elliptic.P256())
	assert.NoError(t, err)

	_, err = engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	err = engine.DeleteKey(ctx, keyID)
	assert.NoError(t, err)
}

func SharedGetKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, key, err := engine.CreateECDSAPrivateKey(ctx, elliptic.P256())
	assert.NoError(t, err)

	signer, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	assert.Equal(t, key, signer)
}

func SharedListKeys(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keys, err := engine.ListPrivateKeyIDs(ctx)
	assert.NoError(t, err)
	assert.Len(t, keys, 0)

	keyID1, _, err := engine.CreateECDSAPrivateKey(ctx, elliptic.P256())
	assert.NoError(t, err)

	keyID2, _, err := engine.CreateECDSAPrivateKey(ctx, elliptic.P256())
	assert.NoError(t, err)

	keys, err = engine.ListPrivateKeyIDs(ctx)
	assert.NoError(t, err)

	assert.Contains(t, keys, keyID1)
	assert.Contains(t, keys, keyID2)

	assert.Len(t, keys, 2)
}

func SharedRenameKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, _, err := engine.CreateECDSAPrivateKey(ctx, elliptic.P256())
	assert.NoError(t, err)

	err = engine.RenameKey(ctx, keyID, "new-key-id")
	assert.NoError(t, err)

	_, err = engine.GetPrivateKeyByID(ctx, keyID)
	assert.Error(t, err)

	signer, err := engine.GetPrivateKeyByID(ctx, "new-key-id")
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

func SharedGetKeyNotFound(t *testing.T, engine CryptoEngine) {
	_, err := engine.GetPrivateKeyByID(context.Background(), "non-existing-key")
	assert.Error(t, err)
}

func sha256Hash(t *testing.T, data []byte) []byte {
	h := sha256.New()
	_, err := h.Write(data)
	assert.NoError(t, err)
	return h.Sum(nil)
}

func SharedTestRSAPSSSignature(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateRSAPrivateKey(ctx, 2048)
	assert.NoError(t, err)

	hashed := sha256Hash(t, []byte("aa"))

	signature, err := signer.Sign(rand.Reader, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	err = rsa.VerifyPSS(signer2.Public().(*rsa.PublicKey), crypto.SHA256, hashed, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})

	assert.NoError(t, err)
}

func SharedTestRSAPKCS1v15Signature(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateRSAPrivateKey(ctx, 2048)
	assert.NoError(t, err)

	hashed := sha256Hash(t, []byte("aa"))

	signature, err := signer.Sign(rand.Reader, hashed, crypto.SHA256)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	err = rsa.VerifyPKCS1v15(signer2.Public().(*rsa.PublicKey), crypto.SHA256, hashed, signature)
	assert.NoError(t, err)
}

func SharedTestECDSASignature(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateECDSAPrivateKey(ctx, elliptic.P256())
	assert.NoError(t, err)

	hashed := sha256Hash(t, []byte("aa"))

	signature, err := signer.Sign(rand.Reader, hashed, crypto.SHA256)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	res := ecdsa.VerifyASN1(signer2.Public().(*ecdsa.PublicKey), hashed, signature)
	assert.True(t, res)
}

func SharedTestImportRSAPrivateKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	assert.NoError(t, err)

	pubKey := key.Public().(*rsa.PublicKey)

	_, importedSigner, err := engine.ImportRSAPrivateKey(ctx, key)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(*rsa.PublicKey)
	assert.Equal(t, pubKey.N, importedPubKey.N)
	assert.Equal(t, pubKey.E, importedPubKey.E)
}

func SharedTestImportECDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	pubKey := key.Public().(*ecdsa.PublicKey)

	_, importedSigner, err := engine.ImportECDSAPrivateKey(ctx, key)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(*ecdsa.PublicKey)
	assert.Equal(t, pubKey.X, importedPubKey.X)
	assert.Equal(t, pubKey.Y, importedPubKey.Y)
}
