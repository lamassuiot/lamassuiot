//go:build !windows
// +build !windows

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"strings"

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
	engineInfo       models.CryptoEngineInfo
	config           crypto11.Config
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
		upperEnvKey := strings.ToUpper(envKey)
		lPkcs11.Debugf("setting env variable %s", upperEnvKey)
		if err := os.Setenv(upperEnvKey, envVal); err != nil {
			lPkcs11.Errorf("could not set env variable %s: %s", upperEnvKey, err)
			return nil, fmt.Errorf("could not set env variable %s: %w", upperEnvKey, err)
		}
	}

	lPkcs11.Debugf("configuring pkcs11 module: \n - ModulePath: %s\n - TokenLabel: %s\n - Pin: ******\n", config.Path, conf.Config.TokenLabel)
	instance, err := crypto11.Configure(config)
	if err != nil {
		lPkcs11.Errorf("could not configure pkcs11 module: %s", err)
		return nil, errors.New("could not configure driver")
	}

	pkcs11ProviderContext := pkcs11.New(conf.Config.ModulePath)
	if pkcs11ProviderContext == nil {
		return nil, fmt.Errorf("could not create pkcs11 context")
	}

	err = pkcs11ProviderContext.Initialize()
	if err != nil && err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		lPkcs11.Errorf("could not initialize pkcs11 context: %s", err)
		return nil, fmt.Errorf("could not initialize pkcs11 context")
	}

	pkcs11ProviderSlots, err := pkcs11ProviderContext.GetSlotList(true)
	if err != nil {
		lPkcs11.Errorf("could not get slot list: %s", err)
		return nil, fmt.Errorf("could not get slot list")
	}

	if len(pkcs11ProviderSlots) == 0 {
		lPkcs11.Errorf("could not get slot list: no slots with tokens available")
		return nil, fmt.Errorf("could not get slot list")
	}

	lPkcs11.Debugf("pkcs11 provider has %d slots", len(pkcs11ProviderSlots))
	var tokenInfo pkcs11.TokenInfo
	var slotID uint
	foundToken := false
	for _, slot := range pkcs11ProviderSlots {
		lPkcs11.Tracef("getting slot '%d' info", slot)
		tokenInfoResp, err := pkcs11ProviderContext.GetTokenInfo(slot)
		if err != nil {
			lPkcs11.Errorf("could not get slot '%d' info. Skipping: %s", slot, err)
			continue
		}

		tokenLabel := strings.TrimSpace(tokenInfoResp.Label)
		lPkcs11.Tracef("slot '%d' has label '%s'", slot, tokenLabel)
		if config.TokenLabel == tokenLabel {
			tokenInfo = tokenInfoResp
			slotID = slot
			foundToken = true
		}
	}

	if !foundToken {
		lPkcs11.Errorf("could not find token with label '%s'", config.TokenLabel)
		return nil, fmt.Errorf("could not find token")
	}

	pkcs11ProviderInfo, err := pkcs11ProviderContext.GetInfo()
	if err != nil {
		lPkcs11.Errorf("could not get provider info: %s", err)
		return nil, fmt.Errorf("could not get info")
	}

	pkcs11SupportedKeys := []models.SupportedKeyTypeInfo{}

	rsaMechanismInfo, err := pkcs11ProviderContext.GetMechanismInfo(slotID, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)})
	if err == nil {
		pkcs11SupportedKeys = append(pkcs11SupportedKeys, models.SupportedKeyTypeInfo{
			Type:  models.KeyType(x509.RSA),
			Sizes: helpers.CalculateRSAKeySizes(int(rsaMechanismInfo.MinKeySize), int(rsaMechanismInfo.MaxKeySize)),
		})
		lPkcs11.Debugf("provider supports RSA keys with sizes %d - %d", rsaMechanismInfo.MinKeySize, rsaMechanismInfo.MaxKeySize)
	} else {
		lPkcs11.Errorf("could not get RSA PKCS mechanism. Provider might not support RSA or something went wrong: %s", err)
	}

	ecdsaMechanismInfo, err := pkcs11ProviderContext.GetMechanismInfo(slotID, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)})
	if err == nil {
		pkcs11SupportedKeys = append(pkcs11SupportedKeys, models.SupportedKeyTypeInfo{
			Type:  models.KeyType(x509.ECDSA),
			Sizes: helpers.CalculateECDSAKeySizes(int(ecdsaMechanismInfo.MinKeySize), int(ecdsaMechanismInfo.MaxKeySize)),
		})
		lPkcs11.Debugf("provider supports ECDSA keys with sizes %d - %d", ecdsaMechanismInfo.MinKeySize, ecdsaMechanismInfo.MaxKeySize)
	} else {
		lPkcs11.Errorf("could not get ECDSA PKCS mechanism. Provider might not support ECDSA or something went wrong: %s", err)
	}

	defaultMeta := map[string]any{
		"lamassu.io/cryptoengine/pkcs11/cryptoki-version": fmt.Sprintf("%b.%b", pkcs11ProviderInfo.CryptokiVersion.Major, pkcs11ProviderInfo.CryptokiVersion.Minor),
		"lamassu.io/cryptoengine/pkcs11/library":          pkcs11ProviderInfo.LibraryDescription,
		"lamassu.io/cryptoengine/pkcs11/manufacturer":     pkcs11ProviderInfo.ManufacturerID,
		"lamassu.io/cryptoengine/pkcs11/model":            tokenInfo.Model,
	}

	meta := helpers.MergeMaps(&defaultMeta, &conf.Metadata)

	return &pkcs11EngineContext{
		logger:           lPkcs11,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lPkcs11),
		slotID:           slotID,
		api:              instance,
		lowApi:           pkcs11ProviderContext,
		engineInfo: models.CryptoEngineInfo{
			Type:              models.PKCS11,
			SecurityLevel:     models.SL2,
			Provider:          pkcs11ProviderInfo.ManufacturerID,
			SupportedKeyTypes: pkcs11SupportedKeys,
			Name:              tokenInfo.Model,
			Metadata:          *meta,
		},
		config: *config,
	}, nil
}

func (hsmContext *pkcs11EngineContext) GetEngineConfig() models.CryptoEngineInfo {
	return hsmContext.engineInfo
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

func (hsmContext *pkcs11EngineContext) GetPrivateKeyByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, hsmContext.logger)
	lFunc.Debugf("reading %s Key", keyID)
	hsmKey, err := hsmContext.api.FindKeyPair(nil, []byte(keyID))
	if err != nil {
		lFunc.Errorf("could not get private key %s. Got error: %s", keyID, err)
		return nil, fmt.Errorf("could not get private key. Got error: %s", err)
	}

	if hsmKey == nil {
		lFunc.Errorf("could not find private key %s", keyID)
		return nil, fmt.Errorf("could not find private key")
	}

	return hsmKey, nil
}

func (hsmContext *pkcs11EngineContext) ListPrivateKeyIDs(ctx context.Context) ([]string, error) {
	lFunc := helpers.ConfigureLogger(ctx, hsmContext.logger)
	lFunc.Debugf("listing private keys")
	keys, err := hsmContext.api.FindAllKeyPairs()
	if err != nil {
		lFunc.Errorf("could not list private keys: %s", err)
	}

	keyIDs := make([]string, 0)
	for _, key := range keys {
		attrs, err := hsmContext.api.GetAttributes(key, []uint{pkcs11.CKA_LABEL})
		if err != nil {
			lFunc.Errorf("could not get key attributes: %s", err)
			continue
		}

		attrsSlice := attrs.ToSlice()
		if len(attrsSlice) == 0 {
			lFunc.Warnf("found a key with no attributes")
			continue
		}

		attr := attrsSlice[0]
		keyID := string(attr.Value)
		keyIDs = append(keyIDs, keyID)
	}

	return keyIDs, nil
}

func (hsmContext *pkcs11EngineContext) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, hsmContext.logger)
	tmpKeyID := uuid.New().String()
	lFunc.Debugf("creating RSA %d key", keySize)
	newSigner, err := hsmContext.api.GenerateRSAKeyPair([]byte(tmpKeyID), keySize)
	if err != nil {
		lFunc.Errorf("could not create '%s' RSA Private Key: %s", tmpKeyID, err)
		return "", nil, err
	}

	keyID, err := hsmContext.softCryptoEngine.EncodePKIXPublicKeyDigest(ctx, newSigner.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key: %s", err)
		return "", nil, err
	}

	err = hsmContext.UpdateKeyName(ctx, tmpKeyID, keyID, PKCS11_KEY_ID)
	if err != nil {
		lFunc.Errorf("could not rename key: %s", err)
		return "", nil, err
	}

	return keyID, newSigner, nil
}

func (hsmContext *pkcs11EngineContext) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, hsmContext.logger)
	tmpKeyID := uuid.New().String()
	lFunc.Debugf("creating ECDSA %d key", curve.Params().BitSize)
	newSigner, err := hsmContext.api.GenerateECDSAKeyPair([]byte(tmpKeyID), curve)
	if err != nil {
		lFunc.Errorf("could not create '%s' ECDSA Private Key: %s", tmpKeyID, err)
		return "", nil, err
	}

	keyID, err := hsmContext.softCryptoEngine.EncodePKIXPublicKeyDigest(ctx, newSigner.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key: %s", err)
		return "", nil, err
	}

	err = hsmContext.UpdateKeyName(ctx, tmpKeyID, keyID, PKCS11_KEY_ID)
	if err != nil {
		lFunc.Errorf("could not rename key: %s", err)
		return "", nil, err
	}

	renamedSigner, err := hsmContext.GetPrivateKeyByID(ctx, keyID)
	if err != nil {
		lFunc.Errorf("could not get renamed key: %s", err)
		return "", nil, err
	}

	return keyID, renamedSigner, nil
}

// define a constant for the key ID using ints and iota

type PKCS11KeyID int

const (
	PKCS11_KEY_ID PKCS11KeyID = iota
	PKCS11_KEY_LABEL
)

func (hsmContext *pkcs11EngineContext) UpdateKeyName(ctx context.Context, oldKeyID string, newKeyID string, keyType PKCS11KeyID) error {
	lFunc := helpers.ConfigureLogger(ctx, hsmContext.logger)
	lFunc.Infof("renaming key from %s to %s", oldKeyID, newKeyID)

	hsmSession, err := hsmContext.lowApi.OpenSession(hsmContext.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		lFunc.Errorf("could not open session: %s", err)
		return err
	}
	defer hsmContext.lowApi.CloseSession(hsmSession)

	// lowApi is a separate pkcs11.Ctx from crypto11's internal context and has never
	// called C_Login. Private key objects are invisible to unauthenticated sessions,
	// so we must log in here. CKR_USER_ALREADY_LOGGED_IN is acceptable — the token
	// is already authenticated and our session inherits that state.
	loginErr := hsmContext.lowApi.Login(hsmSession, pkcs11.CKU_USER, hsmContext.config.Pin)
	if loginErr != nil && loginErr != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		lFunc.Errorf("could not login to HSM session: %s", loginErr)
		return loginErr
	}

	// Rename both the private and public key objects so that crypto11's makeKeyPair
	// can find the public half by matching CKA_ID + CKA_LABEL on both sides.
	// Failing to rename the public key is non-fatal — crypto11 has a CKA_ID-only
	// fallback — but keeping them in sync avoids relying on that fallback.
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
		isPrivate := class == pkcs11.CKO_PRIVATE_KEY
		attrSet := crypto11.NewAttributeSet()
		attrSet.Set(crypto11.CkaClass, class)
		if keyType == PKCS11_KEY_LABEL {
			attrSet.Set(pkcs11.CKA_LABEL, oldKeyID)
		} else {
			attrSet.Set(pkcs11.CKA_ID, oldKeyID)
		}

		keyHandle, err := findKeyWithAttributes(*hsmContext.lowApi, hsmSession, attrSet.ToSlice())
		if err != nil {
			if isPrivate {
				lFunc.Errorf("could not find private key: %s", err)
				return err
			}
			lFunc.Warnf("could not find public key for rename (non-fatal): %s", err)
			continue
		}

		for _, attr := range []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(newKeyID)),
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(newKeyID)),
		} {
			if err := hsmContext.setKeyAttribute(lFunc, hsmSession, attr, *keyHandle, isPrivate); err != nil {
				return err
			}
		}
	}

	return nil
}

func (hsmContext *pkcs11EngineContext) setKeyAttribute(lFunc *logrus.Entry, hsmSession pkcs11.SessionHandle, attr *pkcs11.Attribute, keyHandle pkcs11.ObjectHandle, isPrivate bool) error {
	attrName := pkcs11AttributeName(attr.Type)
	keyKind := "public key"
	if isPrivate {
		keyKind = "private key"
	}

	err := hsmContext.lowApi.SetAttributeValue(hsmSession, keyHandle, []*pkcs11.Attribute{attr})
	if err != nil {
		if strings.Contains(err.Error(), "CKR_ATTRIBUTE_READ_ONLY") {
			lFunc.Warnf("%s attribute %s is read-only, skipping attribute rename", keyKind, attrName)
			return nil
		}
		if isPrivate {
			lFunc.Errorf("could not set private key attribute %s: %s", attrName, err)
			return err
		}
		lFunc.Warnf("could not set public key attribute %s (non-fatal): %s", attrName, err)
		return nil
	}

	lFunc.Infof("set %s attribute %s successfully", keyKind, attrName)
	return nil
}

func (hsmContext *pkcs11EngineContext) RenameKey(ctx context.Context, oldKeyID string, newKeyID string) error {
	return hsmContext.UpdateKeyName(ctx, oldKeyID, newKeyID, PKCS11_KEY_LABEL)
}

func (hsmContext *pkcs11EngineContext) ImportRSAPrivateKey(ctx context.Context, key *rsa.PrivateKey) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, hsmContext.logger)

	keyID, err := hsmContext.softCryptoEngine.EncodePKIXPublicKeyDigest(ctx, key.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}
	lFunc.Debugf("importing RSA key with ID %s", keyID)

	hsmSession, err := hsmContext.lowApi.OpenSession(hsmContext.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		lFunc.Errorf("could not open session: %s", err)
		return "", nil, err
	}
	defer hsmContext.lowApi.CloseSession(hsmSession)

	loginErr := hsmContext.lowApi.Login(hsmSession, pkcs11.CKU_USER, hsmContext.config.Pin)
	if loginErr != nil && loginErr != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		lFunc.Errorf("could not login: %s", loginErr)
		return "", nil, loginErr
	}

	key.Precompute()

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, intToBytes(key.PublicKey.E)),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, key.D.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, key.Primes[0].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, key.Primes[1].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, key.Precomputed.Dp.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, key.Precomputed.Dq.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, key.Precomputed.Qinv.Bytes()),
	}
	if _, err = hsmContext.lowApi.CreateObject(hsmSession, privTemplate); err != nil {
		lFunc.Errorf("could not import RSA private key: %s", err)
		return "", nil, fmt.Errorf("could not import RSA private key: %w", err)
	}

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, intToBytes(key.PublicKey.E)),
	}
	if _, err = hsmContext.lowApi.CreateObject(hsmSession, pubTemplate); err != nil {
		lFunc.Warnf("could not import RSA public key object (non-fatal): %s", err)
	}

	signer, err := hsmContext.GetPrivateKeyByID(ctx, keyID)
	if err != nil {
		lFunc.Errorf("could not retrieve imported RSA key: %s", err)
		return "", nil, err
	}
	return keyID, signer, nil
}

func (hsmContext *pkcs11EngineContext) ImportECDSAPrivateKey(ctx context.Context, key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, hsmContext.logger)

	ecParams, err := marshalEcParamsForCurve(key.Curve)
	if err != nil {
		lFunc.Errorf("unsupported elliptic curve: %s", err)
		return "", nil, err
	}

	rawPoint := elliptic.Marshal(key.Curve, key.PublicKey.X, key.PublicKey.Y)
	ecPoint, err := asn1.Marshal(rawPoint)
	if err != nil {
		lFunc.Errorf("could not marshal EC point: %s", err)
		return "", nil, fmt.Errorf("could not marshal EC point: %w", err)
	}

	keyID, err := hsmContext.softCryptoEngine.EncodePKIXPublicKeyDigest(ctx, key.Public())
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}
	lFunc.Debugf("importing ECDSA key with ID %s", keyID)

	hsmSession, err := hsmContext.lowApi.OpenSession(hsmContext.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		lFunc.Errorf("could not open session: %s", err)
		return "", nil, err
	}
	defer hsmContext.lowApi.CloseSession(hsmSession)

	loginErr := hsmContext.lowApi.Login(hsmSession, pkcs11.CKU_USER, hsmContext.config.Pin)
	if loginErr != nil && loginErr != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		lFunc.Errorf("could not login: %s", loginErr)
		return "", nil, loginErr
	}

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key.D.Bytes()),
	}
	if _, err = hsmContext.lowApi.CreateObject(hsmSession, privTemplate); err != nil {
		lFunc.Errorf("could not import ECDSA private key: %s", err)
		return "", nil, fmt.Errorf("could not import ECDSA private key: %w", err)
	}

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPoint),
	}
	if _, err = hsmContext.lowApi.CreateObject(hsmSession, pubTemplate); err != nil {
		lFunc.Warnf("could not import ECDSA public key object (non-fatal): %s", err)
	}

	signer, err := hsmContext.GetPrivateKeyByID(ctx, keyID)
	if err != nil {
		lFunc.Errorf("could not retrieve imported ECDSA key: %s", err)
		return "", nil, err
	}
	return keyID, signer, nil
}

func (hsmContext *pkcs11EngineContext) DeleteKey(ctx context.Context, keyID string) error {
	lFunc := helpers.ConfigureLogger(ctx, hsmContext.logger)
	lFunc.Debugf("deleting key %s", keyID)

	hsmSession, err := hsmContext.lowApi.OpenSession(hsmContext.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		lFunc.Errorf("could not open session: %s", err)
		return err
	}
	defer hsmContext.lowApi.CloseSession(hsmSession)

	loginErr := hsmContext.lowApi.Login(hsmSession, pkcs11.CKU_USER, hsmContext.config.Pin)
	if loginErr != nil && loginErr != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		lFunc.Errorf("could not login: %s", loginErr)
		return loginErr
	}

	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		}
		handle, err := findKeyWithAttributes(*hsmContext.lowApi, hsmSession, template)
		if err != nil {
			if class == pkcs11.CKO_PRIVATE_KEY {
				lFunc.Errorf("could not find private key %s: %s", keyID, err)
				return fmt.Errorf("could not find key %s: %w", keyID, err)
			}
			lFunc.Warnf("could not find public key %s for deletion (non-fatal): %s", keyID, err)
			continue
		}
		if err := hsmContext.lowApi.DestroyObject(hsmSession, *handle); err != nil {
			if class == pkcs11.CKO_PRIVATE_KEY {
				lFunc.Errorf("could not delete private key %s: %s", keyID, err)
				return fmt.Errorf("could not delete key %s: %w", keyID, err)
			}
			lFunc.Warnf("could not delete public key %s (non-fatal): %s", keyID, err)
		} else {
			lFunc.Infof("deleted %s key object %s", pkcs11ClassName(class), keyID)
		}
	}
	return nil
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

func intToBytes(n int) []byte {
	result := [4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	i := 0
	for i < 3 && result[i] == 0 {
		i++
	}
	return result[i:]
}

func marshalEcParamsForCurve(curve elliptic.Curve) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch curve {
	case elliptic.P224():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	case elliptic.P256():
		oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case elliptic.P384():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case elliptic.P521():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", curve.Params().Name)
	}
	return asn1.Marshal(oid)
}

func pkcs11ClassName(class uint) string {
	switch class {
	case pkcs11.CKO_PRIVATE_KEY:
		return "private"
	case pkcs11.CKO_PUBLIC_KEY:
		return "public"
	default:
		return fmt.Sprintf("class_%d", class)
	}
}

func pkcs11AttributeName(attrType uint) string {
	switch attrType {
	case pkcs11.CKA_LABEL:
		return "CKA_LABEL"
	case pkcs11.CKA_ID:
		return "CKA_ID"
	case pkcs11.CKA_MODIFIABLE:
		return "CKA_MODIFIABLE"
	default:
		return fmt.Sprintf("attr_%d", attrType)
	}
}
