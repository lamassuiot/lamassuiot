package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
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
}

func TestAWSSecretsManagerCryptoEngine(t *testing.T) {
	cleanupBeforeTest, engine, err := prepareSecretsManagerCryptoEngine(t)
	if err != nil {
		t.Fatalf("Error preparing KMS engine: %v", err)
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
		{"RenameKey", cryptoengines.SharedRenameKey},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			defer cleanupBeforeTest()
			tt.function(t, engine)
		})
	}
}

func prepareSecretsManagerCryptoEngine(t *testing.T) (func() error, cryptoengines.CryptoEngine, error) {
	beforeTestCleanup, containerCleanup, conf, err := laws.RunAWSEmulationLocalStackDocker(false)
	if err != nil {
		return nil, nil, err
	}

	t.Cleanup(func() { _ = containerCleanup() })

	logger := logrus.New().WithField("test", "KMS")

	metadata := map[string]interface{}{}

	awsConf, err := laws.GetAwsSdkConfig(*conf)
	if err != nil {
		return nil, nil, err
	}

	engine, err := NewAWSSecretManagerEngine(logger, *awsConf, metadata)
	if err != nil {
		return nil, nil, err
	}

	return beforeTestCleanup, engine, nil
}
