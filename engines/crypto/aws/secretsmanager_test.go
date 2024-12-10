package aws

import (
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
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

func TestAWSSecretsManagerCryptoEngine(t *testing.T) {
	engine := prepareSecretsManagerCryptoEngine(t)

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		// {"DeleteKey", cryptoengines.SharedTestDeleteKey},
		{"GetPrivateKeyByID", cryptoengines.SharedGetKey},
		{"GetPrivateKeyByIDNotFound", cryptoengines.SharedGetKeyNotFound},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tt.function(t, engine)
		})
	}
}

func prepareSecretsManagerCryptoEngine(t *testing.T) cryptoengines.CryptoEngine {
	containerCleanup, conf, err := laws.RunAWSEmulationLocalStackDocker()
	assert.NoError(t, err)

	t.Cleanup(func() { _ = containerCleanup() })

	logger := logrus.New().WithField("test", "CreateRSAPrivateKey")

	metadata := map[string]interface{}{}

	awsConf, err := laws.GetAwsSdkConfig(*conf)
	assert.NoError(t, err)

	engine, err := NewAWSSecretManagerEngine(logger, *awsConf, metadata)
	assert.NoError(t, err)
	assert.NotNil(t, engine)
	return engine
}
