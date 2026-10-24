package cryptoengines

import (
	"context"

	"cloudflare/circl/sign/slhdsa"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

func SharedTestCreateMLDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateMLDSAPrivateKey(ctx, 44)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestCreateSLHDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	// paramSet 1 = slhdsa.SHA2_128s
	keyID, signer, err := engine.CreateSLHDSAPrivateKey(ctx, 1)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestCreateEd25519PrivateKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateEd25519PrivateKey()
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

func SharedTestRSAPSSSignature(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateRSAPrivateKey(ctx, 2048)
	assert.NoError(t, err)

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

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

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

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

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

	signature, err := signer.Sign(rand.Reader, hashed, crypto.SHA256)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	res := ecdsa.VerifyASN1(signer2.Public().(*ecdsa.PublicKey), hashed, signature)
	assert.True(t, res)
}

func SharedTestMLDSASignature(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	keyID, signer, err := engine.CreateMLDSAPrivateKey(ctx, 65)
	assert.NoError(t, err)

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

	_, err = signer.Sign(rand.Reader, hashed, crypto.Hash(0))
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
}

func SharedTestSLHDSASignature(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	// paramSet 5 = slhdsa.SHA2_256s
	keyID, signer, err := engine.CreateSLHDSAPrivateKey(ctx, 5)
	assert.NoError(t, err)

	_, err = signer.Sign(rand.Reader, []byte("message to sign"), crypto.Hash(0))
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())
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

func SharedTestImportMLDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	assert.NoError(t, err)

	pubKey := key.Public().(*mldsa.PublicKey)

	_, importedSigner, err := engine.ImportMLDSAPrivateKey(key)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(*mldsa.PublicKey)
	assert.Equal(t, pubKey.Bytes(), importedPubKey.Bytes())
}

func SharedTestImportSLHDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	_, priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	assert.NoError(t, err)

	pubKey := priv.Public().(slhdsa.PublicKey)

	_, importedSigner, err := engine.ImportSLHDSAPrivateKey(priv)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(slhdsa.PublicKey)
	assert.Equal(t, pubKey, importedPubKey)
}

func SharedTestCreateCompositeMLDSARSAPrivateKey(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	// variant 1 = MLDSA44-RSA2048-PSS-SHA256
	keyID, signer, err := engine.CreateCompositeMLDSARSAPrivateKey(ctx, 1)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	// *x509.CompositePublicKey holds its inner keys as closures (adapter
	// pattern), which reflect.DeepEqual - and so assert.Equal - can never
	// consider equal across two separate instances. Use its dedicated
	// Equal method (bytes-based) instead.
	pubKey := signer.Public().(*x509.CompositePublicKey)
	assert.True(t, pubKey.Equal(signer2.Public()))
}

func SharedTestCompositeMLDSARSASignature(t *testing.T, engine CryptoEngine) {
	ctx := context.Background()
	// variant 3 = MLDSA65-RSA3072-PSS-SHA512
	keyID, signer, err := engine.CreateCompositeMLDSARSAPrivateKey(ctx, 3)
	assert.NoError(t, err)

	_, err = signer.Sign(rand.Reader, []byte("message to sign"), crypto.Hash(0))
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID(ctx, keyID)
	assert.NoError(t, err)

	pubKey := signer.Public().(*x509.CompositePublicKey)
	assert.True(t, pubKey.Equal(signer2.Public()))
}

func SharedTestImportCompositeMLDSARSAPrivateKey(t *testing.T, engine CryptoEngine) {
	// variant 1 = MLDSA44-RSA2048-PSS-SHA256
	algo := x509.CompositeAlgorithms[0]
	_, priv, err := algo.GenerateCompositeKey(rand.Reader)
	assert.NoError(t, err)

	pubKey := priv.Public().(*x509.CompositePublicKey)

	_, importedSigner, err := engine.ImportCompositeMLDSARSAPrivateKey(priv)
	assert.NoError(t, err)

	importedPubKey := importedSigner.Public().(*x509.CompositePublicKey)
	assert.True(t, pubKey.Equal(importedPubKey))
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
