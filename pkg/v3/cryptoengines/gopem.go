package cryptoengines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	log "github.com/sirupsen/logrus"
)

type GoCryptoEngine struct {
	config           models.CryptoEngineProvider
	storageDirectory string
}

func NewGolangPEMEngine(storageDirectory string) CryptoEngine {

	pkcs11ProviderSupportedKeyTypes := []models.SupportedKeyTypeInfo{}

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, models.SupportedKeyTypeInfo{
		Type:        models.KeyType(x509.RSA),
		MinimumSize: 1024,
		MaximumSize: 4096,
	})

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, models.SupportedKeyTypeInfo{
		Type:        models.KeyType(x509.ECDSA),
		MinimumSize: 256,
		MaximumSize: 512,
	})

	return &GoCryptoEngine{
		storageDirectory: storageDirectory,
		config: models.CryptoEngineProvider{
			Type:              models.Golang,
			SecurityLevel:     models.SL0,
			Provider:          "Golang PEM",
			Manufacturer:      "Golang",
			Model:             runtime.Version(),
			SupportedKeyTypes: pkcs11ProviderSupportedKeyTypes,
		},
	}
}

func (p *GoCryptoEngine) GetEngineConfig() models.CryptoEngineProvider {
	return p.config
}

func (p *GoCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	privatePEM, err := ioutil.ReadFile(p.storageDirectory + "/" + keyID)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
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

func (p *GoCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Error("Could not create RSA private key: ", err)
		return nil, err
	}

	return p.ImportRSAPrivateKey(key, keyID)
}

func (p *GoCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return p.ImportECDSAPrivateKey(key, keyID)
}

func (p *GoCryptoEngine) DeleteKey(keyID string) error {
	return os.Remove(p.storageDirectory + "/" + keyID)
}

func (p *GoCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	p.checkAndCreateStorageDir()

	err := ioutil.WriteFile(p.storageDirectory+"/"+keyID, pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
		Type:  "RSA PRIVATE KEY",
	}), 0644)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return p.GetPrivateKeyByID(keyID)
}

func (p *GoCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	p.checkAndCreateStorageDir()

	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(p.storageDirectory+"/"+keyID, pem.EncodeToMemory(&pem.Block{
		Bytes: b,
		Type:  "EC PRIVATE KEY",
	}), 0644)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return p.GetPrivateKeyByID(keyID)
}

func (p *GoCryptoEngine) checkAndCreateStorageDir() {
	if _, err := os.Stat(p.storageDirectory); os.IsNotExist(err) {
		log.Warn(fmt.Sprintf("PEM directory [%s] does not exist. Will create such directory", p.storageDirectory))
		os.MkdirAll(p.storageDirectory, 0755)
	}
}
