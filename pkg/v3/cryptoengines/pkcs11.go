package cryptoengines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/ThalesIgnite/crypto11"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
)

var lPkcs11 *logrus.Entry

type pkcs11EngineContext struct {
	instance *crypto11.Context
	config   models.CryptoEngineInfo
}

func NewPKCS11Engine(logger *logrus.Entry, conf config.PKCS11EngineConfig) (CryptoEngine, error) {
	lPkcs11 = logger.WithField("subsystem-provider", "PKCS11")
	config := &crypto11.Config{
		Path:       conf.ModulePath,
		Pin:        conf.TokenPin,
		TokenLabel: conf.TokenLabel,
	}

	lPkcs11.Debugf("configuring pkcs11 module")
	instance, err := crypto11.Configure(config)
	if err != nil {
		lPkcs11.Errorf("could not configure pkcs11 module: %s", err)
		return nil, errors.New("could not get private key")
	}

	pkcs11ProviderContext := pkcs11.New(conf.ModulePath)
	pkcs11ProviderSlots, err := pkcs11ProviderContext.GetSlotList(true)
	if err != nil {
		lPkcs11.Errorf("could not get slot list: %s", err)
		return nil, fmt.Errorf("could not get slot list")
	}

	lPkcs11.Debugf("pkcs11 provier has %d slots", len(pkcs11ProviderSlots))
	var tokenInfo pkcs11.TokenInfo
	for _, slot := range pkcs11ProviderSlots {
		lPkcs11.Tracef("geting slot '%d' info", slot)
		tokenInfoResp, err := pkcs11ProviderContext.GetTokenInfo(slot)
		if err != nil {
			lPkcs11.Errorf("could not get slot '%d' info. Skipping: %s", slot, err)
			continue
		}

		lPkcs11.Tracef("slot '%d' has label '%s'", slot, tokenInfoResp.Label)
		if config.TokenLabel == tokenInfoResp.Label {
			tokenInfo = tokenInfoResp
		}
	}

	pkcs11ProviderInfo, err := pkcs11ProviderContext.GetInfo()
	if err != nil {
		lPkcs11.Errorf("could not get provider info: %s", err)
		return nil, fmt.Errorf("could not get info")
	}

	pkcs11SupporedKeys := []models.SupportedKeyTypeInfo{}

	rsaMechanismInfo, err := pkcs11ProviderContext.GetMechanismInfo(pkcs11ProviderSlots[0], []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)})
	if err == nil {
		pkcs11SupporedKeys = append(pkcs11SupporedKeys, models.SupportedKeyTypeInfo{
			Type: models.KeyType(x509.ECDSA),
			Sizes: []int{
				int(rsaMechanismInfo.MaxKeySize),
				int(rsaMechanismInfo.MaxKeySize),
			},
		})
		lPkcs11.Debugf("provider supports RSA keys with sizes %d - %d", rsaMechanismInfo.MinKeySize, rsaMechanismInfo.MaxKeySize)
	} else {
		lPkcs11.Errorf("could not get RSA PKCS mechanism. Provider might not support RSA or something went wrong: %s", err)
	}

	ecdsaMechanismInfo, err := pkcs11ProviderContext.GetMechanismInfo(pkcs11ProviderSlots[0], []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)})
	if err == nil {
		pkcs11SupporedKeys = append(pkcs11SupporedKeys, models.SupportedKeyTypeInfo{
			Type: models.KeyType(x509.ECDSA),
			Sizes: []int{
				int(ecdsaMechanismInfo.MinKeySize),
				int(ecdsaMechanismInfo.MaxKeySize),
			},
		})
		lPkcs11.Debugf("provider supports ECDSA keys with sizes %d - %d", ecdsaMechanismInfo.MinKeySize, ecdsaMechanismInfo.MaxKeySize)
	} else {
		lPkcs11.Errorf("could not get ECDSA PKCS mechanism. Provider might not support ECDSA or something went wrong: %s", err)
	}

	defaultMeta := map[string]interface{}{
		"lamassu.io/cryptoengine/pkcs11/cryptoki-version": fmt.Sprintf("%b.%b", pkcs11ProviderInfo.CryptokiVersion.Major, pkcs11ProviderInfo.CryptokiVersion.Minor),
		"lamassu.io/cryptoengine/pkcs11/library":          pkcs11ProviderInfo.LibraryDescription,
		"lamassu.io/cryptoengine/pkcs11/manufacturer":     pkcs11ProviderInfo.ManufacturerID,
		"lamassu.io/cryptoengine/pkcs11/model":            tokenInfo.Model,
	}
	meta := helpers.MergeMaps[interface{}](&defaultMeta, &conf.Metadata)

	return &pkcs11EngineContext{
		instance: instance,
		config: models.CryptoEngineInfo{
			Type:              models.PKCS11,
			SecurityLevel:     models.SL2,
			Provider:          pkcs11ProviderInfo.ManufacturerID,
			SupportedKeyTypes: pkcs11SupporedKeys,
			Name:              tokenInfo.Model,
			Metadata:          *meta,
		},
	}, nil
}

func (hsmContext *pkcs11EngineContext) GetEngineConfig() models.CryptoEngineInfo {
	return hsmContext.config
}

func (hsmContext *pkcs11EngineContext) GetPrivateKeys() []crypto.Signer {
	keys := make([]crypto.Signer, 0)

	hsmKeys, err := hsmContext.instance.FindAllKeyPairs()
	if err != nil {
		lPkcs11.Errorf("could not get private keys from provider: %s", err)
		return keys
	}

	for _, key := range hsmKeys {
		keys = append(keys, key)
	}

	return keys
}

func (hsmContext *pkcs11EngineContext) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	hsmKey, err := hsmContext.instance.FindKeyPair([]byte(keyID), nil)
	if err != nil {
		lPkcs11.Errorf("could not get private key %s from provider: %s", keyID, err)
		return nil, fmt.Errorf("could not get private key")
	}

	return hsmKey, nil
}

func (hsmContext *pkcs11EngineContext) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	newSigner, err := hsmContext.instance.GenerateRSAKeyPair([]byte(keyID), keySize)
	if err != nil {
		lPkcs11.Errorf("could not create '%s' RSA Private Key: %s", keyID, err)
		return nil, err
	}

	return newSigner, nil
}

func (hsmContext *pkcs11EngineContext) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	newSigner, err := hsmContext.instance.GenerateECDSAKeyPair([]byte(keyID), curve)
	if err != nil {
		lPkcs11.Errorf("could not create '%s' ECDSA Private Key: %s", keyID, err)
		return nil, err
	}

	return newSigner, nil
}

func (hsmContext *pkcs11EngineContext) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	return nil, fmt.Errorf("TODO")
}
func (hsmContext *pkcs11EngineContext) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	return nil, fmt.Errorf("TODO")
}
