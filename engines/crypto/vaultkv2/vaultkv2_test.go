package vaultkv2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	vconfig "github.com/lamassuiot/lamassuiot/v2/crypto/vaultkv2/config"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/v2/crypto/vaultkv2/docker"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func testGetPrivateKeyNotFoundOnVault(t *testing.T, engine cryptoengines.CryptoEngine) {
	_, err := engine.GetPrivateKeyByID("not-found")
	assert.Error(t, err)
}

func testGetEngineConfig(t *testing.T, engine cryptoengines.CryptoEngine) {

	config := engine.GetEngineConfig()

	assert.Equal(t, models.VaultKV2, config.Type)
	assert.Equal(t, models.SL1, config.SecurityLevel)
	assert.Equal(t, "Hashicorp", config.Provider)
	assert.Equal(t, "Key Value - V2", config.Name)
	assert.Empty(t, config.Metadata)

	expectedKeyTypes := []models.SupportedKeyTypeInfo{
		{
			Type: models.KeyType(x509.RSA),
			Sizes: []int{
				2048,
				3072,
				4096,
			},
		},
		{
			Type: models.KeyType(x509.ECDSA),
			Sizes: []int{
				224,
				256,
				521,
			},
		},
	}
	assert.Equal(t, expectedKeyTypes, config.SupportedKeyTypes)
}

func testDeleteKeyOnVault(t *testing.T, engine cryptoengines.CryptoEngine) {
	_, err := engine.CreateECDSAPrivateKey(elliptic.P256(), "test-ecdsa")
	assert.NoError(t, err)

	signer, err := engine.GetPrivateKeyByID("test-ecdsa")
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	vaultEngine := engine.(*VaultKV2Engine)
	err = vaultEngine.DeleteKey("test-ecdsa")
	assert.Error(t, err)
	// VaultKV2 supports key deletion, but it should be configured at the vault server level
	// _, err = engine.GetPrivateKeyByID("test-ecdsa")
	// assert.Error(t, err)
}

func TestVaultCryptoEngine(t *testing.T) {
	engine := prepareVaultkv2CryptoEngine(t)

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", SharedTestCreateRSAPrivateKey},
		{"GetPrivateKeyNotFound", testGetPrivateKeyNotFoundOnVault},
		{"GetEngineConfig", testGetEngineConfig},
		{"DeleteKey", testDeleteKeyOnVault},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tt.function(t, engine)
		})
	}

}

func prepareVaultkv2CryptoEngine(t *testing.T) cryptoengines.CryptoEngine {
	vCleanup, vaultConfig, _, err := keyvaultkv2_test.RunHashicorpVaultDocker()
	t.Cleanup(func() { _ = vCleanup() })
	assert.NoError(t, err)

	logger := logrus.New().WithField("test", "VaultKV2")

	ceConfig := vconfig.HashicorpVaultCryptoEngineConfig{
		HashicorpVaultSDK: *vaultConfig,
		ID:                "dockertest-hcpvault-kvv2",
		Metadata:          make(map[string]interface{})}

	engine, err := NewVaultKV2Engine(logger, ceConfig)
	assert.NoError(t, err)

	return engine
}

func SharedTestCreateRSAPrivateKey(t *testing.T, engine cryptoengines.CryptoEngine) {
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

func SharedTestCreateECDSAPrivateKey(t *testing.T, engine cryptoengines.CryptoEngine) {
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
