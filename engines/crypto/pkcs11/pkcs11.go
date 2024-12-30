//go:build !windows
// +build !windows

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/ThalesIgnite/crypto11"
	"github.com/google/uuid"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	pconfig "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/config"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
)

type pkcs11EngineContext struct {
	softCryptoEngine *software.SoftwareCryptoEngine
	api              *crypto11.Context
	slotID           uint
	lowApi           *pkcs11.Ctx
	config           models.CryptoEngineInfo
	logger           *logrus.Entry
}

func NewPKCS11Engine(logger *logrus.Entry, conf config.CryptoEngineConfigAdapter[pconfig.PKCS11Config]) (cryptoengines.CryptoEngine, error) {
	lPkcs11 := logger.WithField("subsystem-provider", "PKCS11")
	config := &crypto11.Config{
		Path:       conf.Config.ModulePath,
		Pin:        string(conf.Config.TokenPin),
		TokenLabel: conf.Config.TokenLabel,
	}

	for envKey, envVal := range conf.Config.ModuleExtraOptions.Env {
		lPkcs11.Debugf("setting env variable %s=%s", envKey, envVal)
		os.Setenv(envKey, envVal)
	}

	lPkcs11.Debugf("configuring pkcs11 module: \n - ModulePath: %s\n - TokenLabel: %s\n - Pin: ******\n", config.Path, conf.Config.TokenLabel)
	instance, err := crypto11.Configure(config)
	if err != nil {
		lPkcs11.Errorf("could not configure pkcs11 module: %s", err)
		return nil, errors.New("could not configure driver")
	}

	pkcs11ProviderContext := pkcs11.New(conf.Config.ModulePath)
	pkcs11ProviderSlots, err := pkcs11ProviderContext.GetSlotList(true)
	if err != nil {
		lPkcs11.Errorf("could not get slot list: %s", err)
		return nil, fmt.Errorf("could not get slot list")
	}

	lPkcs11.Debugf("pkcs11 provier has %d slots", len(pkcs11ProviderSlots))
	var tokenInfo pkcs11.TokenInfo
	var slotID uint
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
			slotID = slot
		}
	}

	pkcs11ProviderInfo, err := pkcs11ProviderContext.GetInfo()
	if err != nil {
		lPkcs11.Errorf("could not get provider info: %s", err)
		return nil, fmt.Errorf("could not get info")
	}

	pkcs11SupportedKeys := []models.SupportedKeyTypeInfo{}

	rsaMechanismInfo, err := pkcs11ProviderContext.GetMechanismInfo(pkcs11ProviderSlots[0], []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)})
	if err == nil {
		pkcs11SupportedKeys = append(pkcs11SupportedKeys, models.SupportedKeyTypeInfo{
			Type:  models.KeyType(x509.RSA),
			Sizes: helpers.CalculateRSAKeySizes(int(rsaMechanismInfo.MinKeySize), int(rsaMechanismInfo.MaxKeySize)),
		})
		lPkcs11.Debugf("provider supports RSA keys with sizes %d - %d", rsaMechanismInfo.MinKeySize, rsaMechanismInfo.MaxKeySize)
	} else {
		lPkcs11.Errorf("could not get RSA PKCS mechanism. Provider might not support RSA or something went wrong: %s", err)
	}

	ecdsaMechanismInfo, err := pkcs11ProviderContext.GetMechanismInfo(pkcs11ProviderSlots[0], []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)})
	if err == nil {
		pkcs11SupportedKeys = append(pkcs11SupportedKeys, models.SupportedKeyTypeInfo{
			Type:  models.KeyType(x509.ECDSA),
			Sizes: helpers.CalculateECDSAKeySizes(int(ecdsaMechanismInfo.MinKeySize), int(ecdsaMechanismInfo.MaxKeySize)),
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
		logger:           lPkcs11,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lPkcs11),
		slotID:           slotID,
		api:              instance,
		lowApi:           pkcs11ProviderContext,
		config: models.CryptoEngineInfo{
			Type:              models.PKCS11,
			SecurityLevel:     models.SL2,
			Provider:          pkcs11ProviderInfo.ManufacturerID,
			SupportedKeyTypes: pkcs11SupportedKeys,
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

	hsmKeys, err := hsmContext.api.FindAllKeyPairs()
	if err != nil {
		hsmContext.logger.Errorf("could not get private keys from provider: %s", err)
		return keys
	}

	for _, key := range hsmKeys {
		keys = append(keys, key)
	}

	return keys
}

func (hsmContext *pkcs11EngineContext) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	hsmContext.logger.Debugf("reading %s Key", keyID)
	hsmKey, err := hsmContext.api.FindKeyPair(nil, []byte(keyID))
	if err != nil {
		hsmContext.logger.Errorf("could not get private key %s. Got error: %s", keyID, err)
		return nil, fmt.Errorf("could not get private key. Got error: %s", err)
	}

	if hsmKey == nil {
		hsmContext.logger.Errorf("could not find private key %s", keyID)
		return nil, fmt.Errorf("could not find private key")
	}

	return hsmKey, nil
}

func (hsmContext *pkcs11EngineContext) CreateRSAPrivateKey(keySize int) (string, crypto.Signer, error) {
	tmpKeyID := uuid.New().String()
	hsmContext.logger.Debugf("creating RSA %d key", keySize)
	newSigner, err := hsmContext.api.GenerateRSAKeyPair([]byte(tmpKeyID), keySize)
	if err != nil {
		hsmContext.logger.Errorf("could not create '%s' RSA Private Key: %s", tmpKeyID, err)
		return "", nil, err
	}

	keyID, err := software.NewSoftwareCryptoEngine(hsmContext.logger).EncodePKIXPublicKeyDigest(newSigner.Public())
	if err != nil {
		hsmContext.logger.Errorf("could not encode public key: %s", err)
		return "", nil, err
	}

	err = hsmContext.renameKey(tmpKeyID, keyID)
	if err != nil {
		hsmContext.logger.Errorf("could not rename key: %s", err)
		return "", nil, err
	}

	return keyID, newSigner, nil
}

func (hsmContext *pkcs11EngineContext) CreateECDSAPrivateKey(curve elliptic.Curve) (string, crypto.Signer, error) {
	tmpKeyID := uuid.New().String()
	hsmContext.logger.Debugf("creating ECDSA %d key", curve.Params().BitSize)
	newSigner, err := hsmContext.api.GenerateECDSAKeyPair([]byte(tmpKeyID), curve)
	if err != nil {
		hsmContext.logger.Errorf("could not create '%s' ECDSA Private Key: %s", tmpKeyID, err)
		return "", nil, err
	}

	keyID, err := software.NewSoftwareCryptoEngine(hsmContext.logger).EncodePKIXPublicKeyDigest(newSigner.Public())
	if err != nil {
		hsmContext.logger.Errorf("could not encode public key: %s", err)
		return "", nil, err
	}

	err = hsmContext.renameKey(tmpKeyID, keyID)
	if err != nil {
		hsmContext.logger.Errorf("could not rename key: %s", err)
		return "", nil, err
	}

	renamedSigner, err := hsmContext.GetPrivateKeyByID(keyID)
	if err != nil {
		hsmContext.logger.Errorf("could not get renamed key: %s", err)
		return "", nil, err
	}

	return keyID, renamedSigner, nil
}

func (hsmContext *pkcs11EngineContext) renameKey(oldKeyID string, newKeyID string) error {
	hsmSession, err := hsmContext.lowApi.OpenSession(hsmContext.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		hsmContext.logger.Errorf("could not open session: %s", err)
		return err
	}
	defer hsmContext.lowApi.CloseSession(hsmSession)

	attrSet := crypto11.NewAttributeSet()
	attrSet.Set(crypto11.CkaClass, pkcs11.CKO_PRIVATE_KEY)
	attrSet.Set(pkcs11.CKA_ID, oldKeyID)

	keyHandle, err := findKeyWithAttributes(*hsmContext.lowApi, hsmSession, attrSet.ToSlice())
	if err != nil {
		hsmContext.logger.Errorf("could not find key: %s", err)
	}

	err = hsmContext.lowApi.SetAttributeValue(hsmSession, *keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(newKeyID)),
		// pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(newKeyID)),
	})
	if err != nil {
		hsmContext.logger.Errorf("could not set key attributes: %s", err)
		return err
	}

	return nil
}

func (hsmContext *pkcs11EngineContext) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	return "", nil, fmt.Errorf("TODO")
}

func (hsmContext *pkcs11EngineContext) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	return "", nil, fmt.Errorf("TODO")
}

func (hsmContext *pkcs11EngineContext) DeleteKey(keyID string) error {
	return fmt.Errorf("TODO")
}

func findKeyWithAttributes(ctx pkcs11.Ctx, sh pkcs11.SessionHandle, template []*pkcs11.Attribute) (handle *pkcs11.ObjectHandle, err error) {
	if err = ctx.FindObjectsInit(sh, template); err != nil {
		return nil, err
	}
	defer func() {
		finalErr := ctx.FindObjectsFinal(sh)
		if err == nil {
			err = finalErr
		}
	}()

	newhandles, _, err := ctx.FindObjects(sh, 1)
	if err != nil {
		return nil, err
	}

	for len(newhandles) > 0 {
		return &newhandles[0], nil
	}

	return nil, errors.New("object not found")
}
