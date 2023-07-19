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
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"

	log "github.com/sirupsen/logrus"
)

type AWSSecretsManagerCryptoEngine struct {
	config    models.CryptoEngineProvider
	smngerCli *secretsmanager.SecretsManager
}

func NewAWSSecretManagerEngine(accessKeyID string, secretAccessKey string, region string) (CryptoEngine, error) {
	httpCli, err := helpers.BuildHTTPClientWithloggger(&http.Client{}, fmt.Sprintf("AWS SecretsManager - %s", accessKeyID))
	if err != nil {
		return nil, err
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
		HTTPClient:  httpCli,
	}))
	smngerCli := secretsmanager.New(sess)

	pkcs11ProviderSupportedKeyTypes := []models.SupportedKeyTypeInfo{}

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, models.SupportedKeyTypeInfo{
		Type:        models.KeyType(x509.RSA),
		MinimumSize: 2048,
		MaximumSize: 4096,
	})

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, models.SupportedKeyTypeInfo{
		Type:        models.KeyType(x509.ECDSA),
		MinimumSize: 256,
		MaximumSize: 512,
	})

	return &AWSSecretsManagerCryptoEngine{
		smngerCli: smngerCli,
		config: models.CryptoEngineProvider{
			Type:              models.AWSSecretsManager,
			SecurityLevel:     models.SL1,
			Provider:          "Amazon Web Services",
			Manufacturer:      "AWS",
			Model:             "Secrets Manager",
			SupportedKeyTypes: pkcs11ProviderSupportedKeyTypes,
		},
	}, nil
}

func (engine *AWSSecretsManagerCryptoEngine) GetEngineConfig() models.CryptoEngineProvider {
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
		log.Error("Could not create RSA private key: ", err)
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
		Name:         &keyID,
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
