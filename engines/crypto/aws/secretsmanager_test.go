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
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	aconfig "github.com/lamassuiot/lamassuiot/v2/crypto/aws/config"
	"github.com/lamassuiot/lamassuiot/v2/crypto/aws/docker"
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

func testDeleteKeyOnSecretsManager(t *testing.T, engine cryptoengines.CryptoEngine) {
	awsengine := engine.(*AWSSecretsManagerCryptoEngine)
	err := awsengine.DeleteKey("test-key")
	assert.EqualError(t, err, "cannot delete key [test-key]. Go to your aws account and do it manually")
}

func testGetPrivateKeyNotFoundOnSecretsManager(t *testing.T, engine cryptoengines.CryptoEngine) {
	_, err := engine.GetPrivateKeyByID("test-key")
	assert.Error(t, err)
}

func TestAWSSecretsManagerCryptoEngine(t *testing.T) {
	engine := prepareSecretsManagerCryptoEngine(t)

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", SharedTestCreateRSAPrivateKey},
		{"GetPrivateKeyNotFound", testGetPrivateKeyNotFoundOnSecretsManager},
		{"DeleteKey", testDeleteKeyOnSecretsManager},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tt.function(t, engine)
		})
	}
}

func prepareSecretsManagerCryptoEngine(t *testing.T) cryptoengines.CryptoEngine {
	containerCleanup, conf, err := docker.RunAWSEmulationLocalStackDocker()
	assert.NoError(t, err)

	t.Cleanup(func() { _ = containerCleanup() })

	logger := logrus.New().WithField("test", "CreateRSAPrivateKey")

	metadata := map[string]interface{}{}

	awsConf, err := aconfig.GetAwsSdkConfig(*conf)
	assert.NoError(t, err)

	engine, err := NewAWSSecretManagerEngine(logger, *awsConf, metadata)
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
