package azure

import (
	"crypto/x509"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	lazure "github.com/lamassuiot/lamassuiot/shared/azure/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewAzureKeyVaultEngine(t *testing.T) {
	logger := logrus.New().WithField("test", "NewAzureKeyVaultEngine")
	metadata := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	// Use the emulator credential so NewClient succeeds without a real vault.
	// The URL is arbitrary here — we are only testing constructor output.
	cred := &lazure.EmulatorCredential{}
	engine, err := NewAzureKeyVaultEngine(logger, "http://localhost:4577/devstoreaccount1-keyvault", cred, true, metadata)

	assert.NoError(t, err)
	assert.NotNil(t, engine)
	assert.IsType(t, &AzureKeyVaultCryptoEngine{}, engine)

	kvEngine := engine.(*AzureKeyVaultCryptoEngine)
	assert.Equal(t, models.CryptoEngineInfo{
		Type:          models.AzureKeyVault,
		SecurityLevel: models.SL1,
		Provider:      "Microsoft Azure",
		Name:          "Key Vault",
		Metadata:      metadata,
		SupportedKeyTypes: []models.SupportedKeyTypeInfo{
			{
				Type:  models.KeyType(x509.RSA),
				Sizes: []int{2048, 3072, 4096},
			},
			{
				Type:  models.KeyType(x509.ECDSA),
				Sizes: []int{256, 384, 521},
			},
		},
	}, kvEngine.GetEngineConfig())
}

func TestAzureKeyVaultCryptoEngine(t *testing.T) {
	t.Skip("Azure Key Vault not yet supported by floci-az emulator")

	cleanupBeforeTest, engine, err := prepareKeyVaultCryptoEngine(t)
	if err != nil {
		t.Fatalf("Error preparing Key Vault engine: %v", err)
	}

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		{"SignRSA_PSS", cryptoengines.SharedTestRSAPSSSignature},
		{"SignRSA_PKCS1v1_5", cryptoengines.SharedTestRSAPKCS1v15Signature},
		{"SignECDSA", cryptoengines.SharedTestECDSASignature},
		{"DeleteKey", cryptoengines.SharedTestDeleteKey},
		{"GetPrivateKeyByID", cryptoengines.SharedGetKey},
		{"GetPrivateKeyByIDNotFound", cryptoengines.SharedGetKeyNotFound},
		{"ListPrivateKeyIDs", cryptoengines.SharedListKeys},
		{"ImportRSAPrivateKey", cryptoengines.SharedTestImportRSAPrivateKey},
		{"ImportECDSAPrivateKey", cryptoengines.SharedTestImportECDSAPrivateKey},
		// RenameKey is intentionally omitted: Azure Key Vault key names are
		// immutable. The method documents this limitation and returns an error.
		{"RenameKey_ReturnsError", testRenameKeyReturnsError},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			defer cleanupBeforeTest()
			tt.function(t, engine)
		})
	}
}

// testRenameKeyReturnsError validates that RenameKey returns an error because
// Azure Key Vault key names are immutable (no alias layer like AWS KMS).
func testRenameKeyReturnsError(t *testing.T, engine cryptoengines.CryptoEngine) {
	err := engine.RenameKey("any-old-id", "any-new-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "renaming keys is not supported")
}

func prepareKeyVaultCryptoEngine(t *testing.T) (func() error, cryptoengines.CryptoEngine, error) {
	beforeTestCleanup, containerCleanup, conf, err := lazure.RunAzureEmulationFlociAZDocker(false)
	if err != nil {
		return nil, nil, err
	}

	t.Cleanup(func() { _ = containerCleanup() })

	logger := logrus.New().WithField("test", "KeyVault")

	metadata := map[string]interface{}{}

	credential, err := lazure.GetAzureCredential(*conf)
	if err != nil {
		return nil, nil, err
	}

	engine, err := NewAzureKeyVaultEngine(logger, conf.VaultURL, credential, true, metadata)
	if err != nil {
		return nil, nil, err
	}

	return beforeTestCleanup, engine, nil
}
