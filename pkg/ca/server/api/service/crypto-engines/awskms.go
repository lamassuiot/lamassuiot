package cryptoengines

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lstoll/awskms"
	log "github.com/sirupsen/logrus"
)

type AWSKMSProviderContext struct {
	config api.EngineProviderInfo
	kmscli *kms.KMS
}

func NewAWSKMSEngine(accessKeyID string, secretAccessKey string, region string) (CryptoEngine, error) {
	httpCli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
		HTTPClient:  httpCli,
	}))
	kmscli := kms.New(sess)

	pkcs11ProviderSupportedKeyTypes := []api.SupportedKeyTypeInfo{}

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, api.SupportedKeyTypeInfo{
		Type:        api.RSA,
		MinimumSize: 2048,
		MaximumSize: 4096,
	})

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, api.SupportedKeyTypeInfo{
		Type:        api.ECDSA,
		MinimumSize: 256,
		MaximumSize: 521,
	})

	return &AWSKMSProviderContext{
		kmscli: kmscli,
		config: api.EngineProviderInfo{
			Provider:          "Amazon Web Services",
			Manufacturer:      "AWS",
			Model:             "KMS",
			CryptokiVersion:   "-",
			Library:           "-",
			SupportedKeyTypes: pkcs11ProviderSupportedKeyTypes,
		},
	}, nil
}

func (p *AWSKMSProviderContext) GetEngineConfig() api.EngineProviderInfo {
	return p.config
}

// func (p *pemProviderContext) GetPrivateKeys() ([]crypto.Signer, error) {
// 	fsEntries, err := os.ReadDir(p.storageDirectory)
// 	if err != nil {
// 		return nil, err
// 	}

// 	signers := []crypto.Signer{}

// 	for _, entry := range fsEntries {
// 		if !entry.IsDir() {
// 			privatePEM, err := ioutil.ReadFile(p.storageDirectory + "/" + entry.Name())
// 			if err != nil {
// 				continue
// 			}
// 			block, _ := pem.Decode(privatePEM)
// 			if block == nil {
// 				return nil, fmt.Errorf("failed to parse PEM block containing the key")
// 			}
// 			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
// 			if err != nil {
// 				return nil, err
// 			}
// 			signers = append(signers, priv)
// 		}
// 	}

// 	return signers, nil
// }

func (p *AWSKMSProviderContext) GetPrivateKeyByID(keyAlias string) (crypto.Signer, error) {
	var keyID = ""
	keys, err := p.kmscli.ListKeys(&kms.ListKeysInput{
		Limit: aws.Int64(100),
	})

	if err != nil {
		return nil, err
	}

	for _, key := range keys.Keys {
		aliases, err := p.kmscli.ListAliases(&kms.ListAliasesInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			continue
		}

		for _, alias := range aliases.Aliases {
			if alias.AliasName == &keyAlias {
				keyID = *key.KeyId
				break
			}
		}

		if keyID == keyAlias {
			break
		}
	}

	if keyID == "" {
		return nil, errors.New("kms key not found")
	}

	return awskms.NewSigner(context.Background(), p.kmscli, keyID)
}

func (p *AWSKMSProviderContext) ImportCAPrivateKey(privateKey api.PrivateKey, keyID string) error {
	return errors.New("not implemented")
}
func (p *AWSKMSProviderContext) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	key, err := p.kmscli.CreateKey(&kms.CreateKeyInput{
		KeyUsage: aws.String("SIGN_VERIFY"),
		KeySpec:  aws.String(fmt.Sprintf("RSA_%d", keySize)),
	})

	if err != nil {
		return nil, err
	}

	log.Debug(fmt.Sprintf("RSA key created with ARN [%s]", *key.KeyMetadata.Arn))

	_, err = p.kmscli.CreateAlias(&kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf("alias/%s", keyID)),
		TargetKeyId: key.KeyMetadata.Arn,
	})

	if err != nil {
		log.Warn(fmt.Sprintf("Could not create alias for key ARN [%s]: ", *key.KeyMetadata.Arn), err)
	}

	return p.GetPrivateKeyByID(keyID)
}

func (p *AWSKMSProviderContext) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	log.Warn("Creating ECDSA key with ", curve.Params().BitSize)
	key, err := p.kmscli.CreateKey(&kms.CreateKeyInput{
		KeyUsage: aws.String("SIGN_VERIFY"),
		KeySpec:  aws.String(fmt.Sprintf("ECC_NIST_P%d", curve.Params().BitSize)),
	})

	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	log.Debug(fmt.Sprintf("ECDSA key created with ARN [%s]", *key.KeyMetadata.Arn))

	_, err = p.kmscli.CreateAlias(&kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf("alias/%s", keyID)),
		TargetKeyId: key.KeyMetadata.Arn,
	})

	if err != nil {
		log.Warn(fmt.Sprintf("Could not create alias for key ARN [%s]: ", *key.KeyMetadata.Arn), err)
	}

	return p.GetPrivateKeyByID(keyID)
}

// func (p *pemProviderContext) DeleteAllKeys() error {
// 	fsEntries, err := os.ReadDir(p.storageDirectory)
// 	if err != nil {
// 		return err
// 	}

// 	for _, entry := range fsEntries {
// 		if !entry.IsDir() {
// 			err = os.Remove(p.storageDirectory + "/" + entry.Name())
// 			if err != nil {
// 				continue
// 			}
// 		}
// 	}

// 	return nil
// }

func (p *AWSKMSProviderContext) DeleteKey(keyID string) error {
	return errors.New(fmt.Sprintf("cannot delete key [%s]. Go to your aws account and do it manually", keyID))
}
