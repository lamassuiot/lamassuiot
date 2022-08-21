package cryptoengines

import (
	"crypto"
	"crypto/elliptic"
	"fmt"

	"github.com/ThalesIgnite/crypto11"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/miekg/pkcs11"
)

type hsmProviderContext struct {
	logger   log.Logger
	instance *crypto11.Context
	config   api.EngineProviderInfo
}

func NewHSMPEngine(logger log.Logger, modulePath string, label string, pin string) (service.CryptoEngine, error) {
	config := &crypto11.Config{
		Path:       modulePath,
		Pin:        pin,
		TokenLabel: label,
	}

	instance, err := crypto11.Configure(config)
	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Error Configure")
		return nil, err
	}

	pkcs11ProviderContext := pkcs11.New(modulePath)
	pkcs11ProviderSlots, err := pkcs11ProviderContext.GetSlotList(true)
	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Error GetSlotList")
		return nil, err
	}

	var tokenInfo pkcs11.TokenInfo
	for _, slot := range pkcs11ProviderSlots {
		tokenInfoResp, err := pkcs11ProviderContext.GetTokenInfo(slot)
		if err != nil {
			continue
		}

		if label == tokenInfoResp.Label {
			tokenInfo = tokenInfoResp
		}
	}

	pkcs11ProviderInfo, err := pkcs11ProviderContext.GetInfo()
	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Error GetInfo")
		return nil, err
	}

	pkcs11ProviderSupportedKeyTypes := []api.SupportedKeyTypeInfo{}

	rsaMechanismInfo, err := pkcs11ProviderContext.GetMechanismInfo(pkcs11ProviderSlots[0], []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)})
	if err == nil {
		pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, api.SupportedKeyTypeInfo{
			Type:        "RSA",
			MinimumSize: int(rsaMechanismInfo.MinKeySize),
			MaximumSize: int(rsaMechanismInfo.MaxKeySize),
		})
	}

	ecdsaMechanismInfo, err := pkcs11ProviderContext.GetMechanismInfo(pkcs11ProviderSlots[0], []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)})
	if err == nil {
		pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, api.SupportedKeyTypeInfo{
			Type:        "ECDSA",
			MinimumSize: int(ecdsaMechanismInfo.MinKeySize),
			MaximumSize: int(ecdsaMechanismInfo.MaxKeySize),
		})
	}

	return &hsmProviderContext{
		logger:   logger,
		instance: instance,
		config: api.EngineProviderInfo{
			Provider:          "HSM",
			Manufacturer:      pkcs11ProviderInfo.ManufacturerID,
			Model:             tokenInfo.Model,
			CryptokiVersion:   fmt.Sprintf("%b.%b", pkcs11ProviderInfo.CryptokiVersion.Major, pkcs11ProviderInfo.CryptokiVersion.Minor),
			Library:           pkcs11ProviderInfo.LibraryDescription,
			SupportedKeyTypes: pkcs11ProviderSupportedKeyTypes,
		},
	}, nil
}

func (hsmContext *hsmProviderContext) GetEngineConfig() api.EngineProviderInfo {
	return hsmContext.config
}

// func (hsmContext *hsmProviderContext) GetPrivateKeys() ([]crypto.Signer, error) {
// 	hsmKeys, err := hsmContext.instance.FindAllKeyPairs()
// 	if err != nil {
// 		level.Debug(hsmContext.logger).Log("msg", "Could not get private keys from HSM", "err", err)
// 		return nil, err
// 	}

// 	keys := make([]crypto.Signer, 0)
// 	for _, key := range hsmKeys {
// 		keys = append(keys, key)
// 	}

// 	return keys, nil
// }

func (hsmContext *hsmProviderContext) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	hsmKey, err := hsmContext.instance.FindKeyPair([]byte(keyID), nil)
	if err != nil {
		level.Debug(hsmContext.logger).Log("msg", "Could not get private keys from HSM", "err", err)
		return nil, err
	}

	return hsmKey, nil
}

func (hsmContext *hsmProviderContext) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	hsmKey, err := hsmContext.GetPrivateKeyByID(keyID)
	if hsmKey != nil {
		level.Warn(hsmContext.logger).Log("msg", "RSA private key already exists and will be overwritten", "err", err)
		err = hsmContext.DeleteKey(keyID)
		if err != nil {
			return nil, err
		}
	}

	newSigner, err := hsmContext.instance.GenerateRSAKeyPairWithLabel([]byte(keyID), []byte(keyID), keySize)
	if err != nil {
		level.Debug(hsmContext.logger).Log("msg", "Could not create RSA private key", "err", err)
		return nil, err
	}

	return newSigner, nil
}

func (hsmContext *hsmProviderContext) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	hsmKey, err := hsmContext.GetPrivateKeyByID(keyID)
	if hsmKey != nil {
		level.Warn(hsmContext.logger).Log("msg", "ECDSA private key already exists and will be overwritten", "err", err)
		err = hsmContext.DeleteKey(keyID)
		if err != nil {
			return nil, err
		}
	}

	newSigner, err := hsmContext.instance.GenerateECDSAKeyPairWithLabel([]byte(keyID), []byte(keyID), curve)
	if err != nil {
		level.Debug(hsmContext.logger).Log("msg", "Could not create ECDSA private key", "err", err)
		return nil, err
	}

	return newSigner, nil
}

// func (hsmContext *hsmProviderContext) DeleteAllKeys() error {
// 	signers, err := hsmContext.instance.FindAllKeyPairs()
// 	if err != nil {
// 		return err
// 	}

// 	for _, signer := range signers {
// 		signer.Delete()
// 	}
// 	return nil
// }

func (hsmContext *hsmProviderContext) DeleteKey(keyID string) error {
	hsmKey, err := hsmContext.instance.FindKeyPair([]byte(keyID), nil)
	if err != nil {
		return err
	}

	err = hsmKey.Delete()
	return err
}
