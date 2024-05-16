package cryptoengines

import (
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	awskmssm_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/aws-kms-sm"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewAWSSecretManagerEngine(t *testing.T) {
	logger := logrus.New().WithField("test", "NewAWSSecretManagerEngine")
	awsConf := aws.Config{}
	metadata := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	engine, err := NewAWSSecretManagerEngine(logger, awsConf, metadata)

	assert.NoError(t, err)
	assert.NotNil(t, engine)
	assert.IsType(t, &AWSSecretsManagerCryptoEngine{}, engine)

	awsEngine := engine.(*AWSSecretsManagerCryptoEngine)
	assert.Equal(t, models.CryptoEngineInfo{
		Type:          models.AWSSecretsManager,
		SecurityLevel: models.SL1,
		Provider:      "Amazon Web Services",
		Name:          "Secrets Manager",
		Metadata:      metadata,
		SupportedKeyTypes: []models.SupportedKeyTypeInfo{
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
		},
	}, awsEngine.GetEngineConfig())
}

func testDeleteKeyOnSecretsManager(t *testing.T, engine CryptoEngine) {
	awsengine := engine.(*AWSSecretsManagerCryptoEngine)
	err := awsengine.DeleteKey("test-key")
	assert.EqualError(t, err, "cannot delete key [test-key]. Go to your aws account and do it manually")
}

func testGetPrivateKeyNotFoundOnSecretsManager(t *testing.T, engine CryptoEngine) {
	_, err := engine.GetPrivateKeyByID("test-key")
	assert.Error(t, err)
}

func TestAWSSecretsManagerCryptoEngine(t *testing.T) {
	engine := prepareSecretsManagerCryptoEngine(t)

	table := []struct {
		name     string
		function func(t *testing.T, engine CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", testCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", testCreateRSAPrivateKey},
		{"GetPrivateKeyNotFound", testGetPrivateKeyNotFoundOnSecretsManager},
		{"DeleteKey", testDeleteKeyOnSecretsManager},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tt.function(t, engine)
		})
	}
}

func prepareSecretsManagerCryptoEngine(t *testing.T) CryptoEngine {
	containerCleanup, conf, err := awskmssm_test.RunAWSEmulationLocalStackDocker()
	assert.NoError(t, err)

	t.Cleanup(func() { _ = containerCleanup() })

	logger := logrus.New().WithField("test", "CreateRSAPrivateKey")

	metadata := map[string]interface{}{}

	awsConf, err := config.GetAwsSdkConfig(*conf)
	assert.NoError(t, err)

	engine, err := NewAWSSecretManagerEngine(logger, *awsConf, metadata)
	assert.NoError(t, err)
	assert.NotNil(t, engine)
	return engine
}
