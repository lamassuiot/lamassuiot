package crypto_engines

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

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
)

type pemProviderContext struct {
	logger           log.Logger
	config           api.EngineProviderInfo
	storageDirectory string
}

func NewGolangPEMEngine(logger log.Logger, storageDirectory string) (service.CryptoEngine, error) {

	pkcs11ProviderSupportedKeyTypes := []api.SupportedKeyTypeInfo{}

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, api.SupportedKeyTypeInfo{
		Type:        "RSA",
		MinimumSize: 1024,
		MaximumSize: 8192,
	})

	return &pemProviderContext{
		logger:           logger,
		storageDirectory: storageDirectory,
		config: api.EngineProviderInfo{
			Provider:          "Golang PEM",
			Manufacturer:      "Golang",
			Model:             "Golang",
			CryptokiVersion:   "-",
			Library:           "-",
			SupportedKeyTypes: pkcs11ProviderSupportedKeyTypes,
		},
	}, nil
}

func (p *pemProviderContext) GetEngineConfig() api.EngineProviderInfo {
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

func (p *pemProviderContext) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
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

func (p *pemProviderContext) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	hsmKey, err := p.GetPrivateKeyByID(keyID)
	if hsmKey != nil {
		level.Warn(p.logger).Log("msg", "RSA private key already exists and will be overwritten", "err", err)
		err = p.DeleteKey(keyID)
		if err != nil {
			return nil, err
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		level.Debug(p.logger).Log("msg", "Could not create RSA private key", "err", err)
		return nil, err
	}

	err = ioutil.WriteFile(p.storageDirectory+"/"+keyID, pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0644)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (p *pemProviderContext) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
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

func (p *pemProviderContext) DeleteKey(keyID string) error {
	return os.Remove(p.storageDirectory + "/" + keyID)
}
