package cryptoengines

import (
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
	keyID, signer, err := engine.CreateRSAPrivateKey(2048)
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

	signer2, err := engine.GetPrivateKeyByID(keyID)
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	err = rsa.VerifyPSS(signer2.Public().(*rsa.PublicKey), crypto.SHA256, hashed, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})

	assert.NoError(t, err)
}

func SharedTestCreateECDSAPrivateKey(t *testing.T, engine CryptoEngine) {
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

func SharedGetKeyNotFound(t *testing.T, engine CryptoEngine) {
	_, err := engine.GetPrivateKeyByID("non-existing-key")
	assert.Error(t, err)
}
