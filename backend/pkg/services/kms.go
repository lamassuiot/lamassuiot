package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

type KMSMiddleware func(services.KMSService) services.KMSService

type Engine struct {
	Default  bool
	TenantID string
	Service  cryptoengines.CryptoEngine
	// DeriveForTenant construye la instancia por tenant de un engine global.
	// Si es nil, el engine global se comparte entre tenants.
	DeriveForTenant TenantEngineDeriver
}

type KMSServiceBackend struct {
	service               services.KMSService
	kmsStorage            storage.KMSKeysRepo
	cryptoEngines         map[string]*cryptoengines.CryptoEngine
	engineTenants         map[string]string
	engineDerivers        map[string]TenantEngineDeriver
	tenantEngines         *tenantEngineCache
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
	engineTenants := map[string]string{}
	engineDerivers := map[string]TenantEngineDeriver{}
	var defaultCryptoEngine *cryptoengines.CryptoEngine
	var defaultCryptoEngineID string

	for engineID, engineInstance := range builder.CryptoEngines {
		engines[engineID] = &engineInstance.Service
		if engineInstance.TenantID != "" {
			engineTenants[engineID] = engineInstance.TenantID
		} else if engineInstance.DeriveForTenant != nil {
			engineDerivers[engineID] = engineInstance.DeriveForTenant
		}
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
		engineTenants:         engineTenants,
		engineDerivers:        engineDerivers,
		tenantEngines:         newTenantEngineCache(),
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
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return nil, err
	}
	info := []*models.CryptoEngineProvider{}
	for engineID, engine := range svc.cryptoEngines {
		engineTenant := svc.engineTenants[engineID]
		if engineTenant != "" && engineTenant != tenantContext.TenantID {
			continue
		}
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

func validateEngineTenant(ctx context.Context, engineID, engineTenant string) error {
	if engineTenant == "" {
		return nil
	}
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil || tenantContext.TenantID != engineTenant {
		return core.ErrTenantResourceAccessDenied
	}
	return nil
}

func (svc *KMSServiceBackend) validateEngineTenant(ctx context.Context, engineID string) error {
	return validateEngineTenant(ctx, engineID, svc.engineTenants[engineID])
}

// parse URIs such as
// pkcs11:token-id=<engineID>;id=<keyID>;type=<keyType>
// pkcs11:token-id=<engineID>;label=<alias>;type=<keyType>
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
func (svc *KMSServiceBackend) getEngineAndSigner(ctx context.Context, engineID, keyID string) (cryptoengines.CryptoEngine, crypto.Signer, error) {
	engine, err := svc.resolveEngine(ctx, engineID)
	if err != nil {
		return nil, nil, err
	}

	signer, err := engine.GetPrivateKeyByID(keyID)
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
	Engine cryptoengines.CryptoEngine
}

func (svc *KMSServiceBackend) initKMSKeyOperation(ctx context.Context, identifier, algorithm string, operationName string, input interface{}) (*kmsOperationSetup, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	// Validate input struct
	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("%s struct validation error: %s", operationName, err)
		return nil, errs.ErrValidateBadRequest
	}

	key, err := svc.GetKey(ctx, services.GetKeyInput{
		Identifier: identifier,
	})
	if err != nil {
		return nil, err
	}

	// Parse algorithm
	hash, isRSA, isPSS, err := parseAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	// Get engine and signer
	engine, signer, err := svc.getEngineAndSigner(ctx, key.EngineID, key.KeyID)
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
	}

	if len(message) != hash.Size() {
		return nil, errors.New("invalid digest size")
	}

	return message, nil
}

func (svc *KMSServiceBackend) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return "", err
	}
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

func (svc *KMSServiceBackend) GetKey(ctx context.Context, input services.GetKeyInput) (*models.Key, error) {
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("GetKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	if strings.HasPrefix(input.Identifier, "pkcs11:") {
		lFunc.Debugf("checking if Key '%s' exists via PKCS11URI", input.Identifier)
		_, keyID, _, err := parsePKCS11ID(input.Identifier)
		if err != nil {
			lFunc.Errorf("failed to parse PKCS11 ID: %s", err)
			return nil, err
		}

		lFunc.Debugf("checking if Key '%s' exists via KeyID", keyID)
		exists, key, err := svc.kmsStorage.SelectExistsByKeyID(ctx, keyID)
		if err != nil {
			lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", keyID, err)
			return nil, err
		}

		if !exists {
			lFunc.Infof("key %s can not be found in storage engine via keyID", keyID)
			return nil, errs.ErrKeyNotFound
		}
		if err := svc.validateEngineTenant(ctx, key.EngineID); err != nil {
			return nil, err
		}

		return key, nil
	} else {

		lFunc.Debugf("checking if Key '%s' exists via KeyID", input.Identifier)
		exists, key, err := svc.kmsStorage.SelectExistsByKeyID(ctx, input.Identifier)
		if err != nil {
			lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.Identifier, err)
			return nil, err
		}

		if !exists {
			lFunc.Infof("key %s can not be found in storage engine via keyID", input.Identifier)
			lFunc.Debugf("checking if Key '%s' exists via Alias", input.Identifier)
			exists, key, err = svc.kmsStorage.SelectExistsByAlias(ctx, input.Identifier)
			if err != nil {
				lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.Identifier, err)
				return nil, err
			}

			if !exists {
				lFunc.Infof("key %s can not be found in storage engine via alias", input.Identifier)
				return nil, errs.ErrKeyNotFound
			}
		}
		if err := svc.validateEngineTenant(ctx, key.EngineID); err != nil {
			return nil, err
		}

		return key, nil
	}
}

func (svc *KMSServiceBackend) GetKeyStats(ctx context.Context, input services.GetKeyStatsInput) (*models.KeyStats, error) {
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	stats := &models.KeyStats{
		KeysDistributionPerEngine:    make(map[string]int),
		KeysDistributionPerAlgorithm: make(map[string]int),
	}

	// Get total count
	totalCount, err := svc.kmsStorage.CountWithFilters(ctx, input.QueryParameters)
	if err != nil {
		lFunc.Errorf("failed to count total keys: %s", err)
		return nil, err
	}
	stats.TotalKeys = totalCount

	// Count keys per engine
	for engineID := range svc.cryptoEngines {
		count, err := svc.kmsStorage.CountByEngineWithFilters(ctx, engineID, input.QueryParameters)
		if err != nil {
			lFunc.Errorf("failed to count keys for engine %s: %s", engineID, err)
			stats.KeysDistributionPerEngine[engineID] = -1
		} else {
			stats.KeysDistributionPerEngine[engineID] = count
		}
	}

	// Count keys per algorithm
	algorithms := []string{"RSA", "ECDSA", "Ed25519"}
	for _, algorithm := range algorithms {
		// Create a combined filter with algorithm
		combinedParams := &resources.QueryParameters{}

		// Copy existing filters
		if input.QueryParameters != nil {
			combinedParams.Filters = append([]resources.FilterOption{}, input.QueryParameters.Filters...)
			combinedParams.Sort = input.QueryParameters.Sort
			combinedParams.PageSize = input.QueryParameters.PageSize
			combinedParams.NextBookmark = input.QueryParameters.NextBookmark
		}

		// Add algorithm filter
		combinedParams.Filters = append(combinedParams.Filters, resources.FilterOption{
			Field:           "algorithm",
			FilterOperation: resources.StringContains,
			Value:           algorithm,
		})

		count, err := svc.kmsStorage.CountWithFilters(ctx, combinedParams)
		if err != nil {
			lFunc.Errorf("failed to count keys for algorithm %s: %s", algorithm, err)
			stats.KeysDistributionPerAlgorithm[algorithm] = -1
		} else {
			stats.KeysDistributionPerAlgorithm[algorithm] = count
		}
	}

	return stats, nil
}

func (svc *KMSServiceBackend) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.Key, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return nil, err
	}
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err = kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("CreateKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	if input.Algorithm == "" || input.Size == 0 {
		lFunc.Error("algorithm and size are required")
		return nil, errs.ErrValidateBadRequest
	}

	engineID := input.EngineID
	if engineID == "" {
		engineID = svc.defaultCryptoEngineID
	}
	engineInstance, err := svc.resolveEngine(ctx, engineID)
	if err != nil {
		lFunc.Errorf("could not resolve engine with id %s: %s", engineID, err)
		return nil, err
	}

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
		keyID, signer, err = engineInstance.CreateRSAPrivateKey(ctx, bits)
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
		keyID, signer, err = engineInstance.CreateECDSAPrivateKey(ctx, curve)
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

	// Initialize tags and metadata with defaults if not provided
	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}

	metadata := input.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	kmsKey := models.Key{
		PKCS11URI:     buildPKCS11ID(engineID, keyID, "private"),
		KeyID:         keyID,
		EngineID:      engineID,
		TenantID:      tenantContext.TenantID,
		Name:          input.Name,
		Aliases:       []string{},
		HasPrivateKey: true,
		Algorithm:     input.Algorithm,
		Size:          input.Size,
		PublicKey:     base64PEM,
		CreationTS:    time.Now(),
		Tags:          tags,
		Metadata:      metadata,
	}

	return svc.kmsStorage.Insert(ctx, &kmsKey)
}

func (svc *KMSServiceBackend) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.Key, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return nil, err
	}
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err = kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("ImportKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// Check if EngineID is provided, otherwise use default
	engineID := input.EngineID
	if engineID == "" {
		engineID = svc.defaultCryptoEngineID
	}
	engineInstance, err := svc.resolveEngine(ctx, engineID)
	if err != nil {
		lFunc.Errorf("could not resolve engine with id %s: %s", engineID, err)
		return nil, err
	}

	var (
		publicKey crypto.PublicKey
		algorithm string
		size      int
	)

	switch k := input.PrivateKey.(type) {
	case *rsa.PrivateKey:
		size = k.N.BitLen()
		algorithm = "RSA"
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		size = k.Params().BitSize
		algorithm = "ECDSA"
		publicKey = &k.PublicKey
	default:
		lFunc.Errorf("unsupported private key type")
		return nil, errors.New("unsupported private key type")
	}

	err = svc.checkKeySpecEngineCompliance(algorithm, size, engineInstance)
	if err != nil {
		lFunc.Errorf("key spec (type and size) is not compliant with the selected engine: %s", err)
		return nil, err
	}

	// 004 T4.5: el keyID se calcula antes de escribir para detectar el
	// duplicado del propio tenant sin tocar el engine.
	keyID, err := software.NewSoftwareCryptoEngine(lFunc).EncodePKIXPublicKeyDigest(publicKey)
	if err != nil {
		lFunc.Errorf("could not compute the key ID: %s", err)
		return nil, errs.ErrKeyImportFailed
	}
	exists, _, err := svc.kmsStorage.SelectExistsByKeyID(ctx, keyID)
	if err != nil {
		lFunc.Errorf("could not check if key %s exists: %s", keyID, err)
		return nil, errs.ErrKeyImportFailed
	}
	if exists {
		lFunc.Infof("key %s already exists in this tenant", keyID)
		return nil, errs.ErrKeyAlreadyExists
	}

	signer, written, err := svc.writeOrAdoptKeyMaterial(lFunc, engineInstance, keyID, input.PrivateKey, publicKey)
	if err != nil {
		return nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		lFunc.Errorf("failed to marshal public key: %s", err)
		svc.removeWrittenKeyMaterial(lFunc, engineInstance, keyID, written)
		return nil, errs.ErrKeyImportFailed
	}

	pemBlockPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	base64PEM := base64.StdEncoding.EncodeToString(pemBlockPub)

	// Initialize tags and metadata with defaults if not provided
	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}

	metadata := input.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	kmsKey := models.Key{
		PKCS11URI:     buildPKCS11ID(engineID, keyID, "private"),
		KeyID:         keyID,
		EngineID:      engineID,
		TenantID:      tenantContext.TenantID,
		Name:          input.Name,
		Aliases:       []string{},
		HasPrivateKey: true,
		Algorithm:     algorithm,
		Size:          size,
		PublicKey:     base64PEM,
		CreationTS:    time.Now(),
		Tags:          tags,
		Metadata:      metadata,
	}

	inserted, err := svc.kmsStorage.Insert(ctx, &kmsKey)
	if err != nil {
		lFunc.Errorf("could not store key %s: %s", keyID, err)
		// Si otra petición del mismo tenant insertó la fila entre la
		// comprobación y la inserción, el material es suyo: no se borra.
		if exists, _, lookupErr := svc.kmsStorage.SelectExistsByKeyID(ctx, keyID); lookupErr == nil && exists {
			return nil, errs.ErrKeyAlreadyExists
		}
		svc.removeWrittenKeyMaterial(lFunc, engineInstance, keyID, written)
		return nil, errs.ErrKeyImportFailed
	}

	return inserted, nil
}

// writeOrAdoptKeyMaterial escribe la clave en el engine del tenant o, si el
// engine ya tiene material con ese keyID y la misma clave pública (huérfano del
// propio tenant), lo adopta sin reescribirlo. written indica si esta llamada
// escribió material.
func (svc *KMSServiceBackend) writeOrAdoptKeyMaterial(lFunc *logrus.Entry, engine cryptoengines.CryptoEngine, keyID string, privateKey any, publicKey crypto.PublicKey) (crypto.Signer, bool, error) {
	if existing, err := engine.GetPrivateKeyByID(keyID); err == nil && existing != nil {
		comparable, ok := existing.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !comparable.Equal(publicKey) {
			lFunc.Errorf("engine material for key %s does not match the imported public key", keyID)
			return nil, false, errs.ErrKeyImportFailed
		}
		lFunc.Infof("adopting existing engine material for key %s", keyID)
		return existing, false, nil
	}

	var (
		writtenID string
		signer    crypto.Signer
		err       error
	)
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		writtenID, signer, err = engine.ImportRSAPrivateKey(k)
	case *ecdsa.PrivateKey:
		writtenID, signer, err = engine.ImportECDSAPrivateKey(k)
	default:
		return nil, false, errors.New("unsupported private key type")
	}
	if err != nil {
		lFunc.Errorf("failed to import private key: %s", err)
		return nil, false, errs.ErrKeyImportFailed
	}
	if writtenID != keyID {
		lFunc.Errorf("engine stored key %s under unexpected ID %s", keyID, writtenID)
		return nil, false, errs.ErrKeyImportFailed
	}
	return signer, true, nil
}

// removeWrittenKeyMaterial borra lo que escribió esta llamada, nunca material
// que ya existía antes.
func (svc *KMSServiceBackend) removeWrittenKeyMaterial(lFunc *logrus.Entry, engine cryptoengines.CryptoEngine, keyID string, written bool) {
	if !written {
		return
	}
	if err := engine.DeleteKey(keyID); err != nil {
		lFunc.Errorf("could not remove key material %s after a failed import: %s", keyID, err)
	}
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

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateKeyMetadataInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	key, err := svc.GetKey(ctx, services.GetKeyInput{
		Identifier: input.ID,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	updatedMetadata, err := chelpers.ApplyPatches[map[string]any](key.Metadata, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to metadata for key '%s': %v", input.ID, err)
		return nil, err
	}

	key.Metadata = *updatedMetadata

	updatedKey, err := svc.kmsStorage.Update(ctx, key)
	if err != nil {
		lFunc.Errorf("failed to update key metadata: %s", err)
		return nil, err
	}

	return updatedKey, nil
}

func (svc *KMSServiceBackend) UpdateKeyAliases(ctx context.Context, input services.UpdateKeyAliasesInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateKeyAliasesInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	key, err := svc.GetKey(ctx, services.GetKeyInput{
		Identifier: input.ID,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	for _, patch := range input.Patches {
		if patch.Op == models.PatchAdd || patch.Op == models.PatchReplace {
			alias, ok := patch.Value.(string)
			if !ok {
				lFunc.Errorf("invalid alias value type for key '%s'", input.ID)
				return nil, fmt.Errorf("invalid alias value type")
			}

			// Check for duplicate aliases
			exist, _, err := svc.kmsStorage.SelectExistsByAlias(ctx, alias)
			if err != nil {
				lFunc.Errorf("failed to check if alias exists for key '%s': %v", input.ID, err)
				return nil, err
			}

			if exist {
				lFunc.Errorf("duplicate alias '%s' found for key '%s'", alias, input.ID)
				return nil, fmt.Errorf("duplicate alias found")
			}
		}
	}

	updatedAliases, err := chelpers.ApplyPatches[[]string](key.Aliases, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to aliases for key '%s': %v", input.ID, err)
		return nil, err
	}

	key.Aliases = *updatedAliases

	updatedKey, err := svc.kmsStorage.Update(ctx, key)
	if err != nil {
		lFunc.Errorf("failed to update key metadata: %s", err)
		return nil, err
	}

	return updatedKey, nil
}

func (svc *KMSServiceBackend) UpdateKeyName(ctx context.Context, input services.UpdateKeyNameInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateKeyNameInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	key, err := svc.GetKey(ctx, services.GetKeyInput{
		Identifier: input.ID,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	key.Name = input.Name
	updatedKey, err := svc.kmsStorage.Update(ctx, key)
	if err != nil {
		lFunc.Errorf("failed to update key name: %s", err)
		return nil, err
	}

	return updatedKey, nil
}

func (svc *KMSServiceBackend) UpdateKeyTags(ctx context.Context, input services.UpdateKeyTagsInput) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateKeyTagsInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	key, err := svc.GetKey(ctx, services.GetKeyInput{
		Identifier: input.ID,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	key.Tags = input.Tags
	updatedKey, err := svc.kmsStorage.Update(ctx, key)
	if err != nil {
		lFunc.Errorf("failed to update key tags: %s", err)
		return nil, err
	}

	return updatedKey, nil
}

func (svc *KMSServiceBackend) DeleteKeyByID(ctx context.Context, input services.GetKeyInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("DeleteKeyByID struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	key, err := svc.GetKey(ctx, services.GetKeyInput{
		Identifier: input.Identifier,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.Identifier, err)
		return err
	}

	engineInstance, err := svc.resolveEngine(ctx, key.EngineID)
	if err != nil {
		lFunc.Errorf("could not resolve engine with id %s: %s", key.EngineID, err)
		return err
	}

	_, err = engineInstance.GetPrivateKeyByID(key.KeyID)
	if err != nil {
		lFunc.Errorf("could not get key from engine: %s", err)
		return fmt.Errorf("key not found")
	}

	err = engineInstance.DeleteKey(key.KeyID)
	if err != nil {
		lFunc.Errorf("delete key error: %s", err)
		return err
	}

	lFunc.Debugf("deleting key %s from storage engine", key.KeyID)
	err = svc.kmsStorage.Delete(ctx, key.KeyID)
	if err != nil {
		lFunc.Errorf("delete by ID error: %s", err)
		return fmt.Errorf("failed to delete key from storage: %w", err)
	}

	lFunc.Infof("key %s deleted successfully", key.KeyID)

	return nil
}

func (svc *KMSServiceBackend) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	// Setup common KMS operation components
	setup, err := svc.initKMSKeyOperation(ctx, input.Identifier, input.Algorithm, "SignMessage", input)
	if err != nil {
		return nil, err
	}

	digest, err := calculateDigest(setup.Hash, input.MessageType, input.Message)
	if err != nil {
		lFunc.Errorf("calculate digest error: %s", err)
		return nil, err
	}

	entropy := software.NewLamassuEntropy(ctx)

	var signature []byte
	if setup.IsRSA {
		if digest == nil {
			return nil, errors.New("digest is nil")
		}
		if setup.IsPSS {
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: setup.Hash}
			signature, err = setup.Signer.Sign(entropy, digest, opts)
			if err != nil {
				lFunc.Errorf("RSA-PSS Sign error: %s", err)
				return nil, err
			}
		} else {
			signature, err = setup.Signer.Sign(entropy, digest, setup.Hash)
			if err != nil {
				lFunc.Errorf("RSA Sign error: %s", err)
				return nil, err
			}
		}
	} else {
		if digest == nil {
			return nil, errors.New("digest is nil")
		}

		signature, err = setup.Signer.Sign(entropy, digest, setup.Hash)
		if err != nil {
			lFunc.Errorf("ECDSA Sign error: %s", err)
			return nil, err
		}
	}

	return &models.MessageSignature{
		Signature: signature,
	}, nil
}

func (svc *KMSServiceBackend) VerifySignature(ctx context.Context, input services.VerifySignInput) (*models.MessageValidation, error) {
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	// Setup common KMS operation components
	setup, err := svc.initKMSKeyOperation(ctx, input.Identifier, input.Algorithm, "VerifySignature", input)
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
