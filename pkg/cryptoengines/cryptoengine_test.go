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

func testCreateRSAPrivateKey(t *testing.T, engine CryptoEngine) {
	signer, err := engine.CreateRSAPrivateKey(2048, "test-rsa-key")
	assert.NoError(t, err)

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

	signature, err := signer.Sign(rand.Reader, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID("test-rsa-key")
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	err = rsa.VerifyPSS(signer2.Public().(*rsa.PublicKey), crypto.SHA256, hashed, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})

	assert.NoError(t, err)
}

func testCreateECDSAPrivateKey(t *testing.T, engine CryptoEngine) {
	signer, err := engine.CreateECDSAPrivateKey(elliptic.P256(), "test-ecdsa-key")
	assert.NoError(t, err)

	h := sha256.New()
	_, err = h.Write([]byte("aa"))
	assert.NoError(t, err)
	hashed := h.Sum(nil)

	signature, err := signer.Sign(rand.Reader, hashed, crypto.SHA256)
	assert.NoError(t, err)

	signer2, err := engine.GetPrivateKeyByID("test-ecdsa-key")
	assert.NoError(t, err)

	assert.Equal(t, signer.Public(), signer2.Public())

	res := ecdsa.VerifyASN1(signer2.Public().(*ecdsa.PublicKey), hashed, signature)
	assert.True(t, res)
}
