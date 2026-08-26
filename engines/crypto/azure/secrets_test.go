package azure

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	lazure "github.com/lamassuiot/lamassuiot/shared/azure/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewAzureKeyVaultSecretsEngine(t *testing.T) {
	logger := logrus.New().WithField("test", "NewAzureKeyVaultSecretsEngine")
	metadata := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	cred := &lazure.EmulatorCredential{}
	engine, err := NewAzureKeyVaultSecretsEngine(logger, "http://localhost:4577/devstoreaccount1-keyvault", cred, true, metadata)

	assert.NoError(t, err)
	assert.NotNil(t, engine)
	assert.IsType(t, &AzureKeyVaultSecretsCryptoEngine{}, engine)

	smEngine := engine.(*AzureKeyVaultSecretsCryptoEngine)
	assert.Equal(t, models.CryptoEngineInfo{
		Type:          models.AzureKeyVaultSecrets,
		SecurityLevel: models.SL1,
		Provider:      "Microsoft Azure",
		Name:          "Key Vault Secrets",
		Metadata:      metadata,
		SupportedKeyTypes: []models.SupportedKeyTypeInfo{
			{
				Type:  models.KeyType(x509.RSA),
				Sizes: []int{1024, 2048, 3072, 4096},
			},
			{
				Type:  models.KeyType(x509.ECDSA),
				Sizes: []int{224, 256, 384, 521},
			},
		},
	}, smEngine.GetEngineConfig())
}

func TestAzureKeyVaultSecretsCryptoEngine(t *testing.T) {
	cleanupBeforeTest, engine, err := prepareKeyVaultSecretsCryptoEngine(t)
	if err != nil {
		t.Fatalf("Error preparing Key Vault Secrets engine: %v", err)
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
		{"RenameKey", cryptoengines.SharedRenameKey},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			defer cleanupBeforeTest()
			tt.function(t, engine)
		})
	}
}

func prepareKeyVaultSecretsCryptoEngine(t *testing.T) (func() error, cryptoengines.CryptoEngine, error) {
	_, containerCleanup, conf, err := lazure.RunAzureEmulationFlociAZDocker(false)
	if err != nil {
		return nil, nil, err
	}

	t.Cleanup(func() { _ = containerCleanup() })

	logger := logrus.New().WithField("test", "KeyVaultSecrets")

	metadata := map[string]interface{}{}

	credential, err := lazure.GetAzureCredential(*conf)
	if err != nil {
		return nil, nil, err
	}

	engine, err := NewAzureKeyVaultSecretsEngine(logger, conf.VaultURL, credential, true, metadata)
	if err != nil {
		return nil, nil, err
	}

	beforeTestCleanup := func() error {
		return beforeTestCleanup(engine.(*AzureKeyVaultSecretsCryptoEngine).secretsCli)
	}

	return beforeTestCleanup, engine, nil
}

func beforeTestCleanup(client *azsecrets.Client) error {
	ctx := context.Background()
	pager := client.NewListSecretPropertiesPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, secret := range page.Value {
			if secret.ID == nil {
				continue
			}

			_, err := client.DeleteSecret(ctx, secret.ID.Name(), nil)
			if err != nil {
				return err
			}

			_, err = client.PurgeDeletedSecret(ctx, secret.ID.Name(), nil)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
