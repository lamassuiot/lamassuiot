package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
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
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines/legacy"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/kmip"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
)

type KMSMiddleware func(services.KMSService) services.KMSService

type Engine struct {
	Default bool
	Service cryptoengines.CryptoEngine
}

type KMSServiceBackend struct {
	service               services.KMSService
	kmsStorage            storage.KMSKeysRepo
	cryptoEngines         map[string]*cryptoengines.CryptoEngine
	backends              map[string]cryptoengines.Backend
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
	backends := map[string]cryptoengines.Backend{}
	var defaultCryptoEngine *cryptoengines.CryptoEngine
	var defaultCryptoEngineID string

	for engineID, engineInstance := range builder.CryptoEngines {
		engines[engineID] = &engineInstance.Service
		// Every key operation goes through the Backend contract. An engine that implements it is used as
		// is; any other is wrapped by the legacy adapter.
		if backend, ok := engineInstance.Service.(cryptoengines.Backend); ok {
			backends[engineID] = backend
		} else {
			backends[engineID] = legacy.Wrap(engineInstance.Service)
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
		backends:              backends,
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
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("GetKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// A key is identified by (key_id, engine_id). A PKCS#11 URI carries the engine in
	// token-id and an alias is unique across engines, so both address a single key. A bare
	// keyID is only a search: it resolves while one engine holds it and is rejected once
	// several do, rather than silently picking a copy.
	if strings.HasPrefix(input.Identifier, "pkcs11:") {
		lFunc.Debugf("checking if Key '%s' exists via PKCS11URI", input.Identifier)
		engineID, keyID, _, err := parsePKCS11ID(input.Identifier)
		if err != nil {
			lFunc.Errorf("failed to parse PKCS11 ID: %s", err)
			return nil, errs.ErrValidateBadRequest
		}

		exists, key, err := svc.kmsStorage.SelectExistsByKeyID(ctx, keyID, engineID)
		if err != nil {
			lFunc.Errorf("something went wrong while checking if key '%s' exists in engine '%s': %s", keyID, engineID, err)
			return nil, err
		}

		if !exists {
			lFunc.Infof("key %s can not be found in engine %s", keyID, engineID)
			return nil, errs.ErrKeyNotFound
		}

		return key, nil
	}

	// A keyID takes precedence over an alias, so an alias can never shadow the key whose
	// keyID it happens to match.
	lFunc.Debugf("checking if Key '%s' exists via KeyID", input.Identifier)
	copies, err := svc.kmsStorage.SelectByKeyID(ctx, input.Identifier)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if key '%s' exists in storage engine: %s", input.Identifier, err)
		return nil, err
	}

	if len(copies) == 1 {
		return copies[0], nil
	}

	if len(copies) > 1 {
		engineIDs := make([]string, len(copies))
		for i, k := range copies {
			engineIDs[i] = k.EngineID
		}
		lFunc.Infof("keyID %s is held by engines %v; an engine must be specified", input.Identifier, engineIDs)
		return nil, errs.ErrKeyEngineRequired
	}

	lFunc.Debugf("checking if Key '%s' exists via Alias", input.Identifier)
	exists, key, err := svc.kmsStorage.SelectExistsByAlias(ctx, input.Identifier)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if alias '%s' exists in storage engine: %s", input.Identifier, err)
		return nil, err
	}

	if !exists {
		lFunc.Infof("key %s can not be found in storage engine via keyID or alias", input.Identifier)
		return nil, errs.ErrKeyNotFound
	}

	return key, nil
}

func (svc *KMSServiceBackend) GetKeysByPublicKey(ctx context.Context, input services.GetKeysByPublicKeyInput) ([]*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("GetKeysByPublicKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// Every crypto engine names its keys this way, so the keyID follows from the public key alone.
	keyID, err := chelpers.PublicKeyDigest(input.PublicKey)
	if err != nil {
		lFunc.Errorf("could not compute the key ID of the public key: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	if input.EngineID == "" {
		keys, err := svc.kmsStorage.SelectByKeyID(ctx, keyID)
		if err != nil {
			lFunc.Errorf("something went wrong while looking up key '%s' in storage engine: %s", keyID, err)
			return nil, err
		}
		return keys, nil
	}

	exists, key, err := svc.kmsStorage.SelectExistsByKeyID(ctx, keyID, input.EngineID)
	if err != nil {
		lFunc.Errorf("something went wrong while looking up key '%s' in engine '%s': %s", keyID, input.EngineID, err)
		return nil, err
	}
	if !exists {
		return []*models.Key{}, nil
	}
	return []*models.Key{key}, nil
}

func (svc *KMSServiceBackend) GetKeyStats(ctx context.Context, input services.GetKeyStatsInput) (*models.KeyStats, error) {
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
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
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
	backend, ok := svc.backends[engineID]
	if !ok {
		lFunc.Errorf("engine with id %s not found", engineID)
		return nil, fmt.Errorf("crypto engine not found")
	}

	err = svc.checkKeySpecEngineCompliance(input.Algorithm, input.Size, engineID)
	if err != nil {
		lFunc.Errorf("key spec (type and size) is not compliant with the selected engine: %s", err)
		return nil, err
	}

	alg, ok := kmipAlgorithm(input.Algorithm)
	if !ok {
		lFunc.Errorf("unsupported algorithm: %s", input.Algorithm)
		return nil, errors.New("unknown or unsupported algorithm")
	}
	if alg == kmip.ECDSA && !slices.Contains([]int{224, 256, 384, 521}, input.Size) {
		lFunc.Error("invalid ECDSA key size")
		return nil, errors.New("invalid ECDSA key size")
	}

	handle, err := backend.Generate(ctx, cryptoengines.GenerateSpec{ObjectType: kmip.PrivateKey, Algorithm: alg, Length: input.Size})
	if err != nil {
		lFunc.Errorf("error creating %s private key: %s", input.Algorithm, err)
		if alg == kmip.RSA {
			return nil, errors.New("failed to create RSA private key")
		}
		return nil, err
	}
	signer, ok := handle.(cryptoengines.Signer)
	if !ok {
		lFunc.Errorf("engine %s returned a private key that cannot sign", engineID)
		return nil, errors.New("unknown or unsupported algorithm")
	}
	keyID := handle.Ref().KeyID

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
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := kmsValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("ImportKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	engineID := input.EngineID
	if engineID == "" {
		engineID = svc.defaultCryptoEngineID
	}
	backend, ok := svc.backends[engineID]
	if !ok {
		lFunc.Errorf("engine with id %s not found", engineID)
		return nil, fmt.Errorf("crypto engine not found")
	}

	var (
		algorithm string
		size      int
	)
	switch k := input.PrivateKey.(type) {
	case *rsa.PrivateKey:
		algorithm, size = "RSA", k.N.BitLen()
	case *ecdsa.PrivateKey:
		algorithm, size = "ECDSA", k.Params().BitSize
	default:
		lFunc.Errorf("unsupported private key type")
		return nil, errors.New("unsupported private key type")
	}

	err = svc.checkKeySpecEngineCompliance(algorithm, size, engineID)
	if err != nil {
		lFunc.Errorf("key spec (type and size) is not compliant with the selected engine: %s", err)
		return nil, err
	}

	handle, err := backend.Import(ctx, cryptoengines.ImportSpec{ObjectType: kmip.PrivateKey, Private: input.PrivateKey})
	if err != nil {
		lFunc.Errorf("failed to import private key: %s", err)
		return nil, errors.New("failed to import private key")
	}
	signer, ok := handle.(cryptoengines.Signer)
	if !ok {
		lFunc.Errorf("engine %s returned a private key that cannot sign", engineID)
		return nil, errors.New("failed to import private key")
	}
	keyID := handle.Ref().KeyID

	publicKey := signer.Public()
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		lFunc.Errorf("failed to marshal public key: %s", err)
		return nil, errors.New("failed to marshal public key")
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

	return svc.kmsStorage.Insert(ctx, &kmsKey)
}

// checkKeySpecEngineCompliance checks that the engine can create keys of that type and size.
func (svc *KMSServiceBackend) checkKeySpecEngineCompliance(keyType string, size int, engineID string) error {
	provider := ""
	if engine, ok := svc.cryptoEngines[engineID]; ok {
		provider = (*engine).GetEngineConfig().Provider
	}
	caps := svc.backends[engineID].Capabilities()

	alg, ok := kmipAlgorithm(keyType)
	if ok && caps.Supports(kmip.OpCreateKeyPair, alg, size) {
		return nil
	}
	if ok && slices.ContainsFunc(caps.Items, func(c cryptoengines.Capability) bool {
		return c.Operation == kmip.OpCreateKeyPair && c.Algorithm == alg
	}) {
		return fmt.Errorf("key size %d is not supported for key type %s in engine %s", size, keyType, provider)
	}

	return fmt.Errorf("key type %s is not supported in engine %s", keyType, provider)
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

			// A keyID wins over an alias when resolving an identifier, so an alias that
			// matches one would never resolve to this key.
			shadowed, err := svc.kmsStorage.SelectByKeyID(ctx, alias)
			if err != nil {
				lFunc.Errorf("failed to check if alias '%s' collides with a keyID: %v", alias, err)
				return nil, err
			}

			if len(shadowed) > 0 {
				lFunc.Errorf("alias '%s' collides with an existing keyID", alias)
				return nil, errs.ErrKeyAliasCollidesWithKeyID
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

	backend, ok := svc.backends[key.EngineID]
	if !ok {
		return fmt.Errorf("engine with id %s not found", key.EngineID)
	}
	ref := keyRef(key)

	_, err = backend.Load(ctx, ref)
	if err != nil {
		lFunc.Errorf("could not get key from engine: %s", err)
		return fmt.Errorf("key not found")
	}

	// The engine copy is only deleted once the row is: a key a certificate references keeps both.
	lFunc.Debugf("deleting key %s (engine %s)", key.KeyID, key.EngineID)
	err = svc.kmsStorage.DeleteWith(ctx, key.KeyID, key.EngineID, func() error {
		return backend.Destroy(ctx, ref)
	})
	if errors.Is(err, errs.ErrKeyInUse) {
		lFunc.Infof("key %s (engine %s) is in use, not deleting it", key.KeyID, key.EngineID)
		return errs.ErrKeyInUse
	}
	if err != nil {
		lFunc.Errorf("delete key error: %s", err)
		return fmt.Errorf("failed to delete key: %w", err)
	}

	lFunc.Infof("key %s deleted successfully", key.KeyID)

	return nil
}
