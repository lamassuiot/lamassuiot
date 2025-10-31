package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type Engine struct {
	Default bool
	Service cryptoengines.CryptoEngine
}

type KMSServiceBackend struct {
	service               services.KMSService
	kmsStorage            storage.KMSKeysRepo
	cryptoEngines         map[string]*cryptoengines.CryptoEngine
	defaultCryptoEngine   *cryptoengines.CryptoEngine
	defaultCryptoEngineID string
	logger                *logrus.Entry
}

type KMSServiceBuilder struct {
	Logger        *logrus.Entry
	CryptoEngines map[string]*Engine
	KMSStorage    storage.KMSKeysRepo
}

var kmsValidator *validator.Validate

func NewKMSService(builder KMSServiceBuilder) (services.KMSService, error) {
	kmsValidator = validator.New()

	engines := map[string]*cryptoengines.CryptoEngine{}
	var defaultCryptoEngine *cryptoengines.CryptoEngine
	var defaultCryptoEngineID string

	for engineID, engineInstance := range builder.CryptoEngines {
		engines[engineID] = &engineInstance.Service
		if engineInstance.Default {
			defaultCryptoEngine = &engineInstance.Service
			defaultCryptoEngineID = engineID
		}
	}

	if defaultCryptoEngine == nil {
		return nil, fmt.Errorf("could not find the default crypto engine")
	}

	svc := &KMSServiceBackend{
		cryptoEngines:         engines,
		defaultCryptoEngine:   defaultCryptoEngine,
		defaultCryptoEngineID: defaultCryptoEngineID,
		kmsStorage:            builder.KMSStorage,
		logger:                builder.Logger,
	}

	svc.service = svc

	return svc, nil
}

func (svc *KMSServiceBackend) Close() {
	//no op
}

func (svc *KMSServiceBackend) SetService(service services.KMSService) {
	svc.service = service
}

func (svc *KMSServiceBackend) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	info := []*models.CryptoEngineProvider{}
	for engineID, engine := range svc.cryptoEngines {
		engineInstance := *engine
		engineInfo := engineInstance.GetEngineConfig()
		info = append(info, &models.CryptoEngineProvider{
			CryptoEngineInfo: engineInfo,
			ID:               engineID,
			Default:          engineID == svc.defaultCryptoEngineID,
		})
	}

	return info, nil
}

func parsePKCS11ID(id string) (engineID, keyID, keyType string, err error) {
	if !strings.HasPrefix(id, "pkcs11:") {
		return "", "", "", errors.New("invalid id format: missing pkcs11 prefix")
	}
	params := strings.TrimPrefix(id, "pkcs11:")
	parts := strings.Split(params, ";")
	m := make(map[string]string)
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	engineID, ok1 := m["token-id"]
	keyID, ok2 := m["id"]
	keyType, ok3 := m["type"]
	if !ok1 || !ok2 || !ok3 {
		return "", "", "", errors.New("invalid id format: missing required fields")
	}
	return engineID, keyID, keyType, nil
}

// Helper to build pkcs11 id format
func buildPKCS11ID(engineID, keyID, keyType string) string {
	return "pkcs11:token-id=" + engineID + ";id=" + keyID + ";type=" + keyType
}

func parseAlgorithm(inputAlgorithm string) (hash crypto.Hash, isRSA, isPSS bool, err error) {
	switch inputAlgorithm {
	case "RSASSA_PKCS1_V1_5_SHA_256":
		isRSA = true
		hash = crypto.SHA256
	case "RSASSA_PKCS1_V1_5_SHA_384":
		isRSA = true
		hash = crypto.SHA384
	case "RSASSA_PKCS1_V1_5_SHA_512":
		isRSA = true
		hash = crypto.SHA512
	case "RSASSA_PSS_SHA_256":
		isRSA = true
		isPSS = true
		hash = crypto.SHA256
	case "RSASSA_PSS_SHA_384":
		isRSA = true
		isPSS = true
		hash = crypto.SHA384
	case "RSASSA_PSS_SHA_512":
		isRSA = true
		isPSS = true
		hash = crypto.SHA512
	case "ECDSA_SHA_256":
		isRSA = false
		hash = crypto.SHA256
	case "ECDSA_SHA_384":
		isRSA = false
		hash = crypto.SHA384
	case "ECDSA_SHA_512":
		isRSA = false
		hash = crypto.SHA512
	default:
		err = errors.New("unsupported algorithm")
	}
	return
}

// Helper to get engine and signer
func (svc *KMSServiceBackend) getEngineAndSigner(engineID, keyID string) (*cryptoengines.CryptoEngine, crypto.Signer, error) {
	engine, ok := svc.cryptoEngines[engineID]
	if !ok {
		return nil, nil, errors.New("engine not found")
	}

	engineInstance := *engine

	signer, err := engineInstance.GetPrivateKeyByID(keyID)
	if err != nil || signer == nil {
		return nil, nil, errors.New("could not get signing key")
	}
	return engine, signer, nil
}

// Common setup for KMS operations (SignMessage and VerifySignature)
type kmsOperationSetup struct {
	Hash   crypto.Hash
	IsRSA  bool
	IsPSS  bool
	Signer crypto.Signer
	Engine *cryptoengines.CryptoEngine
}

func (svc *KMSServiceBackend) initKMSKeyOperation(ctx context.Context, keyID, algorithm string, operationName string, input interface{}) (*kmsOperationSetup, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	// Validate input struct
	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("%s struct validation error: %s", operationName, err)
		return nil, errs.ErrValidateBadRequest
	}

	// Parse PKCS11 ID
	engineID, keyIDParsed, _, err := parsePKCS11ID(keyID)
	if err != nil {
		return nil, errors.New("invalid key id format, expected pkcs11:token-id=<engineID>;id=<keyID>;type=<type>")
	}

	// Check if key exists
	lFunc.Debugf("checking if Key '%s' exists", keyID)
	exists, _, err := svc.kmsStorage.SelectExistsByID(ctx, keyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", keyID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("Key %s can not be found in storage engine", keyID)
		return nil, errs.ErrKeyNotFound
	}

	// Parse algorithm
	hash, isRSA, isPSS, err := parseAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	// Get engine and signer
	engine, signer, err := svc.getEngineAndSigner(engineID, keyIDParsed)
	if err != nil {
		return nil, err
	}

	return &kmsOperationSetup{
		Hash:   hash,
		IsRSA:  isRSA,
		IsPSS:  isPSS,
		Signer: signer,
		Engine: engine,
	}, nil
}

// Helper to calculate digest
func calculateDigest(hash crypto.Hash, messageType models.SignMessageType, message []byte) ([]byte, error) {
	if messageType == models.Raw {
		hasher := hash.New()
		hasher.Write(message)
		return hasher.Sum(nil), nil
	} else {
		if len(message) != hash.Size() {
			return nil, errors.New("invalid digest size")
		}
	}

	return message, nil
}

func (svc *KMSServiceBackend) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	nextBookmark, err := svc.kmsStorage.SelectAll(ctx, storage.StorageListRequest[models.Key]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading all Requests from storage engine: %s", err)
		return "", err
	}

	return nextBookmark, nil
}

func (svc *KMSServiceBackend) GetKeyByID(ctx context.Context, input services.GetKeyByIDInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("GetKeyByIDInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if Key '%s' exists", input.ID)
	exists, key, err := svc.kmsStorage.SelectExistsByID(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("key %s can not be found in storage engine", input.ID)
		return nil, errs.ErrKeyNotFound
	}

	return key, nil
}

func (svc *KMSServiceBackend) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("CreateKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	if input.Algorithm == "" || input.Size == 0 {
		lFunc.Error("algorithm and size are required")
		return nil, errs.ErrValidateBadRequest
	}

	var engine *cryptoengines.CryptoEngine
	engineID := ""
	var ok bool

	if input.EngineID == "" {
		engine, ok = svc.cryptoEngines[svc.defaultCryptoEngineID]
		engineID = svc.defaultCryptoEngineID
	} else {
		engine, ok = svc.cryptoEngines[input.EngineID]
		engineID = input.EngineID
	}

	if !ok {
		lFunc.Errorf("engine with id %s not found", engineID)
		return nil, fmt.Errorf("crypto engine not found")
	}

	engineInstance := *engine

	var (
		keyID  string
		signer crypto.Signer
	)

	err = svc.checkKeySpecEngineCompliance(input.Algorithm, input.Size, engineInstance)
	if err != nil {
		lFunc.Errorf("key spec (type and size) is not compliant with the selected engine: %s", err)
		return nil, err
	}

	switch input.Algorithm {
	case "RSA":
		bits := input.Size
		keyID, signer, err = engineInstance.CreateRSAPrivateKey(bits)
		if err != nil {
			lFunc.Errorf("error creating RSA private key: %s", err)
			return nil, errors.New("failed to create RSA private key")
		}
	case "ECDSA":
		var curve elliptic.Curve
		switch input.Size {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			lFunc.Error("invalid ECDSA key size")
			return nil, errors.New("invalid ECDSA key size")
		}
		keyID, signer, err = engineInstance.CreateECDSAPrivateKey(curve)
		if err != nil {
			lFunc.Errorf("error creating ECDSA private key: %s", err)
			return nil, err
		}
	default:
		lFunc.Errorf("unsupported algorithm: %s", input.Algorithm)
		return nil, errors.New("unknown or unsupported algorithm")
	}

	publicKey := signer.Public()
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		lFunc.Errorf("marshal public key error: %s", err)
		return nil, errors.New("failed to marshal public key")
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	base64PEM := base64.StdEncoding.EncodeToString(pemBlock)

	kmsKey := models.Key{
		ID:         buildPKCS11ID(engineID, keyID, "private"),
		Algorithm:  input.Algorithm,
		Size:       input.Size,
		PublicKey:  base64PEM,
		Status:     models.StatusActive,
		CreationTS: time.Now(),
		Name:       input.Name,
		Metadata:   map[string]any{},
	}

	return svc.kmsStorage.Insert(ctx, &kmsKey)
}

func (svc *KMSServiceBackend) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("ImportKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// Check if EngineID is provided, otherwise use default
	var engine *cryptoengines.CryptoEngine
	engineID := ""
	var ok bool

	if input.EngineID == "" {
		engine, ok = svc.cryptoEngines[svc.defaultCryptoEngineID]
		engineID = svc.defaultCryptoEngineID
	} else {
		engine, ok = svc.cryptoEngines[input.EngineID]
		engineID = input.EngineID
	}

	if !ok {
		lFunc.Errorf("engine with id %s not found", engineID)
		return nil, fmt.Errorf("crypto engine not found")
	}

	engineInstance := *engine

	var (
		keyID     string
		signer    crypto.Signer
		algorithm string
		size      int
	)

	switch k := input.PrivateKey.(type) {
	case *rsa.PrivateKey:
		size = k.N.BitLen()
		algorithm = "RSA"

		err = svc.checkKeySpecEngineCompliance(algorithm, size, engineInstance)
		if err != nil {
			lFunc.Errorf("key spec (type and size) is not compliant with the selected engine: %s", err)
			return nil, err
		}

		keyID, signer, err = engineInstance.ImportRSAPrivateKey(k)
	case *ecdsa.PrivateKey:
		size = k.Params().BitSize
		algorithm = "ECDSA"

		err = svc.checkKeySpecEngineCompliance(algorithm, size, engineInstance)
		if err != nil {
			lFunc.Errorf("key spec (type and size) is not compliant with the selected engine: %s", err)
			return nil, err
		}

		keyID, signer, err = engineInstance.ImportECDSAPrivateKey(k)
	default:
		lFunc.Errorf("unsupported private key type")
		return nil, errors.New("unsupported private key type")
	}
	if err != nil {
		lFunc.Errorf("failed to import private key: %s", err)
		return nil, errors.New("failed to import private key")
	}

	publicKey := signer.Public()
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		lFunc.Errorf("failed to marshal public key: %s", err)
		return nil, errors.New("failed to marshal public key")
	}

	pemBlockPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	base64PEM := base64.StdEncoding.EncodeToString(pemBlockPub)

	kmsKey := models.Key{
		ID:         buildPKCS11ID(engineID, keyID, "private"),
		Algorithm:  algorithm,
		Size:       size,
		PublicKey:  base64PEM,
		Status:     models.StatusActive,
		CreationTS: time.Now(),
		Name:       input.Name,
		Metadata:   map[string]any{},
	}

	return svc.kmsStorage.Insert(ctx, &kmsKey)
}

func (svc *KMSServiceBackend) checkKeySpecEngineCompliance(keyType string, size int, engine cryptoengines.CryptoEngine) error {
	engineConfig := engine.GetEngineConfig()
	for _, spec := range engineConfig.SupportedKeyTypes {
		if spec.Type.String() == keyType {
			if slices.Contains(spec.Sizes, size) {
				return nil
			} else {
				return fmt.Errorf("key size %d is not supported for key type %s in engine %s", size, keyType, engineConfig.Provider)
			}
		}
	}

	return fmt.Errorf("key type %s is not supported in engine %s", keyType, engineConfig.Provider)
}

func (svc *KMSServiceBackend) UpdateKeyMetadata(ctx context.Context, input services.UpdateKeyMetadataInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateKeyMetadataInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, key, err := svc.kmsStorage.SelectExistsByID(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("key %s can not be found in storage engine", input.ID)
		return nil, errs.ErrKeyNotFound
	}

	updatedMetadata, err := chelpers.ApplyPatches(key.Metadata, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to metadata for key '%s': %v", input.ID, err)
		return nil, err
	}

	key.Metadata = updatedMetadata

	updatedKey, err := svc.kmsStorage.Update(ctx, key)
	if err != nil {
		lFunc.Errorf("failed to update key metadata: %s", err)
		return nil, err
	}

	return updatedKey, nil
}

func (svc *KMSServiceBackend) UpdateKeyAlias(ctx context.Context, input services.UpdateKeyAliasInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateKeyAliasInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, key, err := svc.kmsStorage.SelectExistsByID(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("key %s can not be found in storage engine", input.ID)
		return nil, errs.ErrKeyNotFound
	}

	key.Name = input.Alias
	updatedKey, err := svc.kmsStorage.Update(ctx, key)
	if err != nil {
		lFunc.Errorf("failed to update key alias: %s", err)
		return nil, err
	}

	return updatedKey, nil
}

func (svc *KMSServiceBackend) UpdateKeyID(ctx context.Context, input services.UpdateKeyIDInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateKeyIDInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, key, err := svc.kmsStorage.SelectExistsByID(ctx, input.CurrentID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.CurrentID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("key %s can not be found in storage engine", input.CurrentID)
		return nil, errs.ErrKeyNotFound
	}

	key.ID = input.NewID
	updatedKey, err := svc.kmsStorage.Update(ctx, key)
	if err != nil {
		lFunc.Errorf("failed to update key ID: %s", err)
		return nil, err
	}

	return updatedKey, nil
}

func (svc *KMSServiceBackend) DeleteKeyByID(tx context.Context, input services.GetKeyByIDInput) error {
	lFunc := chelpers.ConfigureLogger(tx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("DeleteKeyByID struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	engineID, keyID, _, err := parsePKCS11ID(input.ID)
	if err != nil {
		return fmt.Errorf("invalid key id format: %w", err)
	}

	engine, ok := svc.cryptoEngines[engineID]
	if !ok {
		return fmt.Errorf("engine with id %s not found", engineID)
	}
	engineInstance := *engine

	_, err = engineInstance.GetPrivateKeyByID(keyID)
	if err != nil {
		lFunc.Errorf("could not get key from engine: %s", err)
		return fmt.Errorf("key not found")
	}

	err = engineInstance.DeleteKey(keyID)
	if err != nil {
		lFunc.Errorf("delete key error: %s", err)
		return err
	}

	lFunc.Debugf("deleting key %s from storage engine", input.ID)
	err = svc.kmsStorage.Delete(tx, input.ID)
	if err != nil {
		lFunc.Errorf("delete by ID error: %s", err)
		return fmt.Errorf("failed to delete key from storage: %w", err)
	}

	lFunc.Infof("key %s deleted successfully", input.ID)

	return nil
}

func (svc *KMSServiceBackend) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	// Setup common KMS operation components
	setup, err := svc.initKMSKeyOperation(ctx, input.KeyID, input.Algorithm, "SignMessage", input)
	if err != nil {
		return nil, err
	}

	digest, err := calculateDigest(setup.Hash, input.MessageType, input.Message)
	if err != nil {
		lFunc.Errorf("calculate digest error: %s", err)
		return nil, err
	}

	var signature []byte
	if setup.IsRSA {
		if digest == nil {
			return nil, errors.New("digest is nil")
		}
		if setup.IsPSS {
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: setup.Hash}
			signature, err = setup.Signer.Sign(rand.Reader, digest, opts)
			if err != nil {
				lFunc.Errorf("RSA-PSS Sign error: %s", err)
				return nil, err
			}
		} else {
			signature, err = setup.Signer.Sign(rand.Reader, digest, setup.Hash)
			if err != nil {
				lFunc.Errorf("RSA Sign error: %s", err)
				return nil, err
			}
		}
	} else {
		if digest == nil {
			return nil, errors.New("digest is nil")
		}
		signature, err = setup.Signer.Sign(rand.Reader, digest, setup.Hash)
		if err != nil {
			lFunc.Errorf("ECDSA Sign error: %s", err)
			return nil, err
		}
	}

	return &models.MessageSignature{
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (svc *KMSServiceBackend) VerifySignature(ctx context.Context, input services.VerifySignInput) (*models.MessageValidation, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	// Setup common KMS operation components
	setup, err := svc.initKMSKeyOperation(ctx, input.KeyID, input.Algorithm, "VerifySignature", input)
	if err != nil {
		return nil, err
	}

	publicKey := setup.Signer.Public()

	digest, err := calculateDigest(setup.Hash, input.MessageType, input.Message)
	if err != nil {
		lFunc.Errorf("calculate digest error: %s", err)
		return nil, err
	}

	if setup.IsRSA {
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("key is not RSA key")
		}
		if setup.IsPSS {
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: setup.Hash}
			err = rsa.VerifyPSS(pub, setup.Hash, digest, input.Signature, opts)
			if err != nil {
				lFunc.Errorf("RSA-PSS verify error: %s", err)
				return &models.MessageValidation{
					Valid: false,
				}, nil
			}
			return &models.MessageValidation{
				Valid: true,
			}, nil
		} else {
			err = rsa.VerifyPKCS1v15(pub, setup.Hash, digest, input.Signature)
			if err != nil {
				lFunc.Errorf("RSA verify error: %s", err)
				return &models.MessageValidation{
					Valid: false,
				}, nil
			}
			return &models.MessageValidation{
				Valid: true,
			}, nil
		}
	} else {
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("key is not ECDSA key")
		}
		if !ecdsa.VerifyASN1(pub, digest, input.Signature) {
			return &models.MessageValidation{
				Valid: false,
			}, nil
		}
		return &models.MessageValidation{
			Valid: true,
		}, nil
	}
}
