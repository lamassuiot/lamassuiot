package cryptoengines

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/ThalesIgnite/crypto11"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/miekg/pkcs11"
)

type HsmProviderContext struct {
	logger          log.Logger
	instance        *crypto11.Context
	config          api.EngineProviderInfo
	providerContext *pkcs11.Ctx
	modulePath      string
	hsmSlot         uint
	pin             string
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
	var slotID uint
	for _, slot := range pkcs11ProviderSlots {
		tokenInfoResp, err := pkcs11ProviderContext.GetTokenInfo(slot)
		if err != nil {
			continue
		}

		if label == tokenInfoResp.Label {
			tokenInfo = tokenInfoResp
			slotID = slot
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

	return &HsmProviderContext{
		logger:     logger,
		modulePath: modulePath,
		hsmSlot:    slotID,
		pin:        pin,
		instance:   instance,
		config: api.EngineProviderInfo{
			Provider:          "HSM",
			Manufacturer:      pkcs11ProviderInfo.ManufacturerID,
			Model:             tokenInfo.Model,
			CryptokiVersion:   fmt.Sprintf("%b.%b", pkcs11ProviderInfo.CryptokiVersion.Major, pkcs11ProviderInfo.CryptokiVersion.Minor),
			Library:           pkcs11ProviderInfo.LibraryDescription,
			SupportedKeyTypes: pkcs11ProviderSupportedKeyTypes,
		},
		providerContext: pkcs11ProviderContext,
	}, nil
}

func (hsmContext *HsmProviderContext) GetEngineConfig() api.EngineProviderInfo {
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

func (hsmContext *HsmProviderContext) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	hsmKey, err := hsmContext.instance.FindKeyPair([]byte(keyID), nil)
	if err != nil {
		level.Debug(hsmContext.logger).Log("msg", "Could not get private keys from HSM", "err", err)
		return nil, err
	}

	return hsmKey, nil
}

func (hsmContext *HsmProviderContext) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
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

func (hsmContext *HsmProviderContext) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
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

func (hsmContext *HsmProviderContext) DeleteKey(keyID string) error {
	hsmKey, err := hsmContext.instance.FindKeyPair([]byte(keyID), nil)
	if err != nil {
		return err
	}

	err = hsmKey.Delete()
	return err
}

func (hsmContext *HsmProviderContext) ImportRSAKeyPair(signerKeyID string, privateKey *rsa.PrivateKey) error {
	hsmCtx := pkcs11.New(hsmContext.modulePath)
	hsmSession, err := hsmCtx.OpenSession(hsmContext.hsmSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}
	defer hsmCtx.CloseSession(hsmSession)

	attributes := crypto11.NewAttributeSet()
	err = attributes.Set(crypto11.CkaId, signerKeyID)
	if err != nil {
		return err
	}

	keyHandlers, err := findKeysWithAttributes(hsmCtx, &hsmSession, attributes.ToSlice())
	if err != nil {
		return err
	}

	fmt.Println(len(keyHandlers))
	keyHandler := keyHandlers[1]

	derKey := x509.MarshalPKCS1PrivateKey(privateKey)

	err = hsmCtx.EncryptInit(hsmSession, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, make([]byte, 16))}, keyHandler)
	if err != nil {
		return err
	}

	wrappedKey, err := hsmCtx.Encrypt(hsmSession, derKey)
	if err != nil {
		return err
	}

	privateKeyAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
	}

	importKeyMechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, nil),
	}

	h, err := hsmContext.providerContext.UnwrapKey(hsmSession, importKeyMechanism, keyHandler, wrappedKey, privateKeyAttrs)
	fmt.Println(h)

	return err
}

func findKeysWithAttributes(context *pkcs11.Ctx, session *pkcs11.SessionHandle, template []*pkcs11.Attribute) (handles []pkcs11.ObjectHandle, err error) {
	if err = context.FindObjectsInit(*session, template); err != nil {
		return nil, err
	}
	defer func() {
		finalErr := context.FindObjectsFinal(*session)
		if err == nil {
			err = finalErr
		}
	}()

	newhandles, _, err := context.FindObjects(*session, 20)
	if err != nil {
		return nil, err
	}

	for len(newhandles) > 0 {
		handles = append(handles, newhandles...)

		newhandles, _, err = context.FindObjects(*session, 20)
		if err != nil {
			return nil, err
		}
	}

	return handles, nil
}
