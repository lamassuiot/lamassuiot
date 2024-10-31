package aws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/cryptoengines"
	chelpers "github.com/lamassuiot/lamassuiot/v2/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	awsce "github.com/lamassuiot/lamassuiot/v2/crypto/aws"
	aconfig "github.com/lamassuiot/lamassuiot/v2/crypto/aws/config"
	awsplatform_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/aws-platform"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewAWSKMSEngine(t *testing.T) {
	logger := logrus.New().WithField("test", "NewAWSKMSEngine")
	awsConf := aws.Config{}
	metadata := map[string]interface{}{
		"key": "value",
	}

	engine, err := awsce.NewAWSKMSEngine(logger, awsConf, metadata)

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
	awsengine := engine.(*awsce.AWSKMSCryptoEngine)
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
		{"CreateECDSAPrivateKey", SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", SharedTestCreateRSAPrivateKey},
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

	awsConf, err := aconfig.GetAwsSdkConfig(*conf)
	assert.NoError(t, err)

	engine, err := awsce.NewAWSKMSEngine(logger, *awsConf, metadata)
	assert.NoError(t, err)
	assert.NotNil(t, engine)
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
