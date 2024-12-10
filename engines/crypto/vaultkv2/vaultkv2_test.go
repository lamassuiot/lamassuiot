package vaultkv2

import (
	"crypto/x509"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	vconfig "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/config"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/docker"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

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

func TestVaultCryptoEngine(t *testing.T) {
	engine := prepareVaultkv2CryptoEngine(t)

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		{"DeleteKey", cryptoengines.SharedTestDeleteKey},
		{"GetPrivateKeyByID", cryptoengines.SharedGetKey},
		{"GetPrivateKeyByIDNotFound", cryptoengines.SharedGetKeyNotFound},
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

	ceConfig := config.CryptoEngineConfigAdapter[vconfig.HashicorpVaultSDK]{
		ID:       "dockertest-hcpvault-kvv2",
		Metadata: make(map[string]interface{}),
		Type:     config.HashicorpVaultProvider,
		Config:   *vaultConfig,
	}

	engine, err := NewVaultKV2Engine(logger, ceConfig)
	assert.NoError(t, err)

	return engine
}
