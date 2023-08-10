package cryptoengines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

var lAWSSM *logrus.Entry

type AWSSecretsManagerCryptoEngine struct {
	config    models.CryptoEngineInfo
	smngerCli *secretsmanager.SecretsManager
}

func NewAWSSecretManagerEngine(logger *logrus.Entry, conf config.AWSSDKConfig) (CryptoEngine, error) {
	lAWSSM = logger.WithField("subsystem-provider", "AWS-SecretsManger")

	httpCli, err := helpers.BuildHTTPClientWithTracerLogger(http.DefaultClient, lAWSSM)
	if err != nil {
		return nil, err
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(conf.Region),
		Credentials: credentials.NewStaticCredentials(conf.AccessKeyID, conf.SecretAccessKey, ""),
		HTTPClient:  httpCli,
	}))

	smngerCli := secretsmanager.New(sess)

	return &AWSSecretsManagerCryptoEngine{
		smngerCli: smngerCli,
		config: models.CryptoEngineInfo{
			Type:          models.AWSSecretsManager,
			SecurityLevel: models.SL1,
			Provider:      "Amazon Web Services",
			Name:          "Secrets Manager",
			Metadata:      conf.Metadata,
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
						512,
					},
				},
			},
		},
	}, nil
}

func (engine *AWSSecretsManagerCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return engine.config
}

func (engine *AWSSecretsManagerCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(keyID),
	}

	result, err := engine.smngerCli.GetSecretValue(input)
	if err != nil {
		return nil, err
	}

	// Decrypts secret using the associated KMS key.
	var secretString string = *result.SecretString
	var keyMap map[string]string

	err = json.Unmarshal([]byte(secretString), &keyMap)
	if err != nil {
		return nil, err
	}

	b64Key, ok := keyMap["key"]
	if !ok {
		return nil, fmt.Errorf("'key' not found in secret")
	}

	pemBytes, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}

}

func (engine *AWSSecretsManagerCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		lAWSSM.Error("Could not create RSA private key: ", err)
		return nil, err
	}

	return engine.ImportRSAPrivateKey(key, keyID)
}

func (engine *AWSSecretsManagerCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return engine.ImportECDSAPrivateKey(key, keyID)
}

func (engine *AWSSecretsManagerCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	keyBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
		Type:  "RSA PRIVATE KEY",
	})

	b64Key := base64.StdEncoding.EncodeToString(keyBytes)
	keyVal := `{"key": "` + b64Key + `"}`

	_, err := engine.smngerCli.CreateSecret(&secretsmanager.CreateSecretInput{
		Name:         aws.String(keyID),
		SecretString: aws.String(keyVal),
	})

	if err != nil {
		return nil, err
	}

	return key, nil
}

func (engine *AWSSecretsManagerCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyBytes = pem.EncodeToMemory(&pem.Block{
		Bytes: keyBytes,
		Type:  "EC PRIVATE KEY",
	})

	b64Key := base64.StdEncoding.EncodeToString(keyBytes)
	keyVal := `{"key": "` + b64Key + `"}`

	_, err = engine.smngerCli.CreateSecret(&secretsmanager.CreateSecretInput{
		Name:         &keyID,
		SecretString: aws.String(keyVal),
	})

	if err != nil {
		return nil, err
	}

	return key, nil
}

func (engine *AWSSecretsManagerCryptoEngine) DeleteKey(keyID string) error {
	return fmt.Errorf("cannot delete key [%s]. Go to your aws account and do it manually", keyID)
}
