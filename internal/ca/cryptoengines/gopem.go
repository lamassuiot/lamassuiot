package cryptoengines

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/lamassuiot/lamassuiot/pkg/models"
	log "github.com/sirupsen/logrus"
)

type GoCryptoEngine struct {
	config           models.CryptoEngineProvider
	storageDirectory string
}

func NewGolangPEMEngine(storageDirectory string) (CryptoEngine, error) {

	pkcs11ProviderSupportedKeyTypes := []models.SupportedKeyTypeInfo{}

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, models.SupportedKeyTypeInfo{
		Type:        "RSA",
		MinimumSize: 1024,
		MaximumSize: 4096,
	})

	return &GoCryptoEngine{
		storageDirectory: storageDirectory,
		config: models.CryptoEngineProvider{
			Provider:          "Golang PEM",
			Manufacturer:      "Golang",
			Model:             runtime.Version(),
			SupportedKeyTypes: pkcs11ProviderSupportedKeyTypes,
		},
	}, nil
}

func (p *GoCryptoEngine) GetEngineConfig() models.CryptoEngineProvider {
	return p.config
}

func (p *GoCryptoEngine) GetPrivateKeys() ([]crypto.Signer, error) {
	fsEntries, err := os.ReadDir(p.storageDirectory)
	if err != nil {
		return nil, err
	}

	signers := []crypto.Signer{}

	for _, entry := range fsEntries {
		if !entry.IsDir() {
			privatePEM, err := ioutil.ReadFile(p.storageDirectory + "/" + entry.Name())
			if err != nil {
				continue
			}
			block, _ := pem.Decode(privatePEM)
			if block == nil {
				return nil, fmt.Errorf("failed to parse PEM block containing the key")
			}
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			signers = append(signers, priv)
		}
	}

	return signers, nil
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

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func (p *GoCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	hsmKey, err := p.GetPrivateKeyByID(keyID)
	if hsmKey != nil {
		log.Warn("RSA private key already exists and will be overwritten: ", err)
		err = p.DeleteKey(keyID)
		if err != nil {
			return nil, err
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Error("Could not create RSA private key: ", err)
		return nil, err
	}

	if _, err := os.Stat(p.storageDirectory); os.IsNotExist(err) {
		log.Warn(fmt.Sprintf("PEM directory [%s] does not exist. Will create such directory", p.storageDirectory))
		os.MkdirAll(p.storageDirectory, 0755)
	}

	err = ioutil.WriteFile(p.storageDirectory+"/"+keyID, pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0644)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return key, nil
}

func (p *GoCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	return nil, errors.New("TODO")
}

func (p *GoCryptoEngine) DeleteAllKeys() error {
	fsEntries, err := os.ReadDir(p.storageDirectory)
	if err != nil {
		return err
	}

	for _, entry := range fsEntries {
		if !entry.IsDir() {
			err = os.Remove(p.storageDirectory + "/" + entry.Name())
			if err != nil {
				continue
			}
		}
	}

	return nil
}

func (p *GoCryptoEngine) DeleteKey(keyID string) error {
	return os.Remove(p.storageDirectory + "/" + keyID)
}
