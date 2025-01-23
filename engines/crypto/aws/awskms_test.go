package aws

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
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

	_, _, err = engine.ImportRSAPrivateKey(key)
	assert.EqualError(t, err, "KMS does not support asymmetric key import")
}

func testImportECDSAKeyOnKMS(t *testing.T, engine cryptoengines.CryptoEngine) {
	key, err := chelpers.GenerateECDSAKey(elliptic.P256())
	assert.NoError(t, err)

	_, _, err = engine.ImportECDSAPrivateKey(key)
	assert.EqualError(t, err, "KMS does not support asymmetric key import")
}

func TestAWSKMSCryptoEngine(t *testing.T) {
	cleanupBeforeTest, engine, err := prepareKMSCryptoEngine(t)
	if err != nil {
		t.Fatalf("Error preparing KMS engine: %v", err)
	}

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		//TODO: LocalStack does not support RSA_PSS with fixed salt length. AWS KMS DOES support it. Follow issues:
		// - https://github.com/localstack/localstack/pull/11649
		// - https://github.com/localstack/localstack/issues/9602
		// {"SignRSA_PSS", cryptoengines.SharedTestRSAPSSSignature},
		{"SignRSA_PKCS1v1_5", cryptoengines.SharedTestRSAPKCS1v15Signature},
		{"SignECDSA", cryptoengines.SharedTestECDSASignature},
		// {"DeleteKey", cryptoengines.SharedTestDeleteKey},
		{"GetPrivateKeyByID", cryptoengines.SharedGetKey},
		{"GetPrivateKeyByIDNotFound", cryptoengines.SharedGetKeyNotFound},
		{"ImportRSAKey", testImportRSAKeyOnKMS},
		{"ImportECDSAKey", testImportECDSAKeyOnKMS},
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

func prepareKMSCryptoEngine(t *testing.T) (func() error, cryptoengines.CryptoEngine, error) {
	beforeTestCleanup, containerCleanup, conf, err := laws.RunAWSEmulationLocalStackDocker()
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

	engine, err := NewAWSKMSEngine(logger, *awsConf, metadata)
	if err != nil {
		return nil, nil, err
	}

	return beforeTestCleanup, engine, nil
}
