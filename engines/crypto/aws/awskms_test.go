package aws

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/cryptoengines"
	chelpers "github.com/lamassuiot/lamassuiot/v2/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	awsplatform_test "github.com/lamassuiot/lamassuiot/v2/crypto/aws/docker"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewAWSKMSEngine(t *testing.T) {
	logger := logrus.New().WithField("test", "NewAWSKMSEngine")
	awsConf := aws.Config{}
	metadata := map[string]interface{}{
		"key": "value",
	}

	engine, err := NewAWSKMSEngine(logger, awsConf, metadata)

	assert.NoError(t, err)
	assert.NotNil(t, engine)

	expectedConfig := models.CryptoEngineInfo{
		Type:          models.AWSKMS,
		SecurityLevel: models.SL2,
		Provider:      "Amazon Web Services",
		Name:          "KMS",
		Metadata:      metadata,
		SupportedKeyTypes: []models.SupportedKeyTypeInfo{
			{
				Type: models.KeyType(x509.RSA),
				Sizes: []int{
					1024,
					2048,
					3072,
					4096,
				},
			},
			{
				Type: models.KeyType(x509.ECDSA),
				Sizes: []int{
					256,
					384,
					521,
				},
			},
		},
	}

	assert.Equal(t, expectedConfig, engine.GetEngineConfig())
}
func testDeleteKeyOnKMS(t *testing.T, engine cryptoengines.CryptoEngine) {
	awsengine := engine.(*AWSKMSCryptoEngine)
	err := awsengine.DeleteKey("test-key")
	assert.EqualError(t, err, "cannot delete key [test-key]. Go to your aws account and do it manually")
}

func testImportRSAKeyOnKMS(t *testing.T, engine cryptoengines.CryptoEngine) {
	key, err := chelpers.GenerateRSAKey(2048)
	assert.NoError(t, err)

	_, err = engine.ImportRSAPrivateKey(key, "imported-rsa-key")
	assert.EqualError(t, err, "KMS does not support asymmetric key import")
}

func testImportECDSAKeyOnKMS(t *testing.T, engine cryptoengines.CryptoEngine) {
	key, err := chelpers.GenerateECDSAKey(elliptic.P256())
	assert.NoError(t, err)

	_, err = engine.ImportECDSAPrivateKey(key, "imported-ecdsa-key")
	assert.EqualError(t, err, "KMS does not support asymmetric key import")
}

func testGetPrivateKeyNotFoundOnKMS(t *testing.T, engine cryptoengines.CryptoEngine) {
	_, err := engine.GetPrivateKeyByID("test-unknown-key")
	assert.EqualError(t, err, "kms key not found")
}

func TestAWSKMSCryptoEngine(t *testing.T) {
	engine := prepareKMSCryptoEngine(t)

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		{"GetPrivateKeyNotFound", testGetPrivateKeyNotFoundOnKMS},
		{"DeleteKey", testDeleteKeyOnKMS},
		{"ImportRSAKey", testImportRSAKeyOnKMS},
		{"ImportECDSAKey", testImportECDSAKeyOnKMS},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tt.function(t, engine)
		})
	}
}

func prepareKMSCryptoEngine(t *testing.T) cryptoengines.CryptoEngine {
	containerCleanup, conf, err := awsplatform_test.RunAWSEmulationLocalStackDocker()
	assert.NoError(t, err)

	t.Cleanup(func() { _ = containerCleanup() })

	logger := logrus.New().WithField("test", "KMS")

	metadata := map[string]interface{}{}

	awsConf, err := cconfig.GetAwsSdkConfig(*conf)
	assert.NoError(t, err)

	engine, err := NewAWSKMSEngine(logger, *awsConf, metadata)
	assert.NoError(t, err)
	assert.NotNil(t, engine)
	return engine
}
