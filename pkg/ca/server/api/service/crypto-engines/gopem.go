package cryptoengines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
)

type pemProviderContext struct {
	config           api.EngineProviderInfo
	storageDirectory string
}

func NewGolangPEMEngine(storageDirectory string) (CryptoEngine, error) {

	pkcs11ProviderSupportedKeyTypes := []api.SupportedKeyTypeInfo{}

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, api.SupportedKeyTypeInfo{
		Type:        "RSA",
		MinimumSize: 1024,
		MaximumSize: 4096,
	})

	return &pemProviderContext{
		storageDirectory: storageDirectory,
		config: api.EngineProviderInfo{
			Manufacturer:      "Golang",
			Provider:          "Golang x509",
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

func (p *pemProviderContext) ImportCAPrivateKey(privateKey api.PrivateKey, keyID string) error {
	if privateKey.KeyType == api.ECDSA {
		ecdsaKey, _ := privateKey.Key.(*ecdsa.PrivateKey)
		if _, err := os.Stat(p.storageDirectory); os.IsNotExist(err) {
			log.Warn(fmt.Sprintf("PEM directory [%s] does not exist. Will create such directory", p.storageDirectory))
			os.MkdirAll(p.storageDirectory, 0755)
		}

		ecdsaBytes, err := x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(p.storageDirectory+"/"+keyID, pem.EncodeToMemory(&pem.Block{
			Bytes: ecdsaBytes,
		}), 0644)
		if err != nil {
			fmt.Println(err)
			return err
		}
	} else {
		rsaKey, _ := privateKey.Key.(*rsa.PrivateKey)

		if _, err := os.Stat(p.storageDirectory); os.IsNotExist(err) {
			log.Warn(fmt.Sprintf("PEM directory [%s] does not exist. Will create such directory", p.storageDirectory))
			os.MkdirAll(p.storageDirectory, 0755)
		}
		err := ioutil.WriteFile(p.storageDirectory+"/"+keyID, pem.EncodeToMemory(&pem.Block{
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}), 0644)
		if err != nil {
			fmt.Println(err)
			return err
		}
	}
	return nil
}
func (p *pemProviderContext) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
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
