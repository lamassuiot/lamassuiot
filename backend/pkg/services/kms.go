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
	"math/big"
	"strings"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type KMSMiddleware func(services.KMSService) services.KMSService

type KMSServiceBackend struct {
	service               services.KMSService
	cryptoEngines         map[string]*cryptoengines.CryptoEngine
	defaultCryptoEngine   *cryptoengines.CryptoEngine
	defaultCryptoEngineID string
	logger                *logrus.Entry
}

type KMSServiceBuilder struct {
	Logger        *logrus.Entry
	CryptoEngines map[string]*Engine
}

func NewKMSService(builder KMSServiceBuilder) (services.KMSService, error) {

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

	svc := KMSServiceBackend{
		cryptoEngines:         engines,
		defaultCryptoEngine:   defaultCryptoEngine,
		defaultCryptoEngineID: defaultCryptoEngineID,
		logger:                builder.Logger,
	}

	svc.service = &svc

	return &svc, nil
}

func (svc *KMSServiceBackend) SetService(service services.KMSService) {
	svc.service = service
}

// Helper to parse pkcs11 id format: pkcs11:token-id=<engineID>;id=<keyID>;type=<type>
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

func (svc *KMSServiceBackend) GetKeys(tx context.Context) ([]*models.KeyInfo, error) {
	lFunc := chelpers.ConfigureLogger(tx, svc.logger)

	var keys []*models.KeyInfo

	for engineID, engine := range svc.cryptoEngines {
		engineInstance := *engine
		PrivateKeyIDs, err := engineInstance.ListPrivateKeyIDs()
		if err != nil {
			lFunc.Errorf("GetKeys - ListPrivateKeyIDs error: %s", err)
			return nil, err
		} else {
			for _, keyID := range PrivateKeyIDs {
				signer, err := engineInstance.GetPrivateKeyByID(keyID)
				if err != nil {
					lFunc.Errorf("GetKeys - GetPrivateKeyByID error: %s", err)
					return nil, err
				}
				if signer == nil {
					lFunc.Errorf("GetKeys - GetPrivateKeyByID returned nil for keyID: %s", keyID)
					return nil, err
				}

				publicKey := signer.Public()

				var (
					algorithm string
					size      string
					pubBytes  []byte
					pemType   string
				)

				keyType := "private"
				switch pk := publicKey.(type) {
				case *rsa.PublicKey:
					algorithm = "RSA"
					size = fmt.Sprintf("%d", pk.Size()*8)
					pubBytes, err = x509.MarshalPKIXPublicKey(pk)
					pemType = "PUBLIC KEY"
				case *ecdsa.PublicKey:
					algorithm = "ECDSA"
					size = fmt.Sprintf("%d", pk.Params().BitSize)
					pubBytes, err = x509.MarshalPKIXPublicKey(pk)
					pemType = "PUBLIC KEY"
				default:
					lFunc.Errorf("GetKeys - Unsupported public key type for keyID: %s", keyID)
					continue
				}
				if err != nil {
					lFunc.Errorf("GetKeys - Marshal public key error: %s", err)
					return nil, err
				}

				pemBlock := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: pubBytes})
				base64PEM := base64.StdEncoding.EncodeToString(pemBlock)

				keys = append(keys, &models.KeyInfo{
					ID:        buildPKCS11ID(engineID, keyID, keyType),
					Algorithm: algorithm,
					Size:      size,
					PublicKey: base64PEM,
				})
			}
		}
	}

	// If no keys were found, return an empty slice instead of nil
	// This is to ensure that the caller can always expect a slice, even if it's empty.
	if keys == nil {
		return []*models.KeyInfo{}, nil
	}

	return keys, nil
}

func (svc *KMSServiceBackend) GetKeyByID(tx context.Context, input services.GetByIDInput) (*models.KeyInfo, error) {
	lFunc := chelpers.ConfigureLogger(tx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetByIDInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	engineID, keyID, keyType, err := parsePKCS11ID(input.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid key id format: %w", err)
	}

	engine, ok := svc.cryptoEngines[engineID]
	if !ok {
		return nil, fmt.Errorf("engine with id %s not found", engineID)
	}
	engineInstance := *engine

	signer, err := engineInstance.GetPrivateKeyByID(keyID)
	if err != nil {
		lFunc.Errorf("GetKey - GetPrivateKeyByID error: %s", err)
		return nil, err
	}
	if signer == nil {
		lFunc.Errorf("GetKey - GetPrivateKeyByID returned nil for keyID: %s", keyID)
		return nil, fmt.Errorf("key not found")
	}

	publicKey := signer.Public()

	var (
		algorithm string
		size      string
		pubBytes  []byte
		pemType   string
	)

	switch pk := publicKey.(type) {
	case *rsa.PublicKey:
		algorithm = "RSA"
		size = fmt.Sprintf("%d", pk.Size()*8)
		pubBytes, err = x509.MarshalPKIXPublicKey(pk)
		pemType = "PUBLIC KEY"
	case *ecdsa.PublicKey:
		algorithm = "ECDSA"
		size = fmt.Sprintf("%d", pk.Params().BitSize)
		pubBytes, err = x509.MarshalPKIXPublicKey(pk)
		pemType = "PUBLIC KEY"
	default:
		lFunc.Errorf("GetKey - Unsupported public key type for keyID: %s", keyID)
		return nil, fmt.Errorf("unsupported public key type")
	}
	if err != nil {
		lFunc.Errorf("GetKey - Marshal public key error: %s", err)
		return nil, err
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: pubBytes})
	base64PEM := base64.StdEncoding.EncodeToString(pemBlock)

	return &models.KeyInfo{
		ID:        buildPKCS11ID(engineID, keyID, keyType),
		Algorithm: algorithm,
		Size:      size,
		PublicKey: base64PEM,
	}, nil
}

func (svc *KMSServiceBackend) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.KeyInfo, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("CreateKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	if input.Algorithm == "" || input.Size == "" {
		lFunc.Error("CreateKey - Algorithm and Size are required")
		return nil, errs.ErrValidateBadRequest
	}

	engine, ok := svc.cryptoEngines[svc.defaultCryptoEngineID]
	if !ok {
		lFunc.Errorf("CreateKey - Engine with id %s not found", svc.defaultCryptoEngineID)
		return nil, fmt.Errorf("default crypto engine not found")
	}

	engineInstance := *engine

	var (
		keyID  string
		signer crypto.Signer
	)

	switch input.Algorithm {
	case "RSA":
		var bits int
		_, err = fmt.Sscanf(input.Size, "%d", &bits)
		if err != nil || bits < 1024 {
			lFunc.Error("CreateKey - Invalid RSA key size")
			return nil, errors.New("invalid RSA key size, must be at least 1024 bits")
		}
		keyID, signer, err = engineInstance.CreateRSAPrivateKey(bits)
		if err != nil {
			lFunc.Errorf("CreateKey - CreateRSAPrivateKey error: %s", err)
			return nil, errors.New("failed to create RSA private key")
		}
	case "ECDSA":
		var curve elliptic.Curve
		switch input.Size {
		case "224":
			curve = elliptic.P224()
		case "256":
			curve = elliptic.P256()
		case "384":
			curve = elliptic.P384()
		case "521":
			curve = elliptic.P521()
		default:
			lFunc.Error("CreateKey - Invalid ECDSA key size")
			return nil, errors.New("invalid ECDSA key size")
		}
		keyID, signer, err = engineInstance.CreateECDSAPrivateKey(curve)
		if err != nil {
			lFunc.Errorf("CreateKey - CreateECDSAPrivateKey error: %s", err)
			return nil, err
		}
	default:
		lFunc.Errorf("CreateKey - Unsupported algorithm: %s", input.Algorithm)
		return nil, errors.New("unknown or unsupported algorithm")
	}

	publicKey := signer.Public()
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		lFunc.Errorf("CreateKey - Marshal public key error: %s", err)
		return nil, errors.New("failed to marshal public key")
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	base64PEM := base64.StdEncoding.EncodeToString(pemBlock)

	return &models.KeyInfo{
		ID:        buildPKCS11ID(svc.defaultCryptoEngineID, keyID, "private"),
		Algorithm: input.Algorithm,
		Size:      input.Size,
		PublicKey: base64PEM,
	}, nil
}

func (svc *KMSServiceBackend) DeleteKeyByID(tx context.Context, input services.GetByIDInput) error {
	lFunc := chelpers.ConfigureLogger(tx, svc.logger)

	err := validate.Struct(input)
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

	err = engineInstance.DeleteKey(keyID)
	if err != nil {
		lFunc.Errorf("DeleteKeyByID - DeleteKey error: %s", err)
		return err
	}

	return nil
}

func (svc *KMSServiceBackend) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("SignMessage struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	engineID, keyID, _, err := parsePKCS11ID(input.KeyID)
	if err != nil {
		return nil, errors.New("invalid key id format, expected pkcs11:token-id=<engineID>;id=<keyID>;type=<type>")
	}

	var hash crypto.Hash
	var isRSA bool

	switch input.Algorithm {
	case "RSASSA_PKCS1_v1_5_SHA256":
		isRSA = true
		hash = crypto.SHA256
	case "RSASSA_PKCS1_v1_5_SHA384":
		isRSA = true
		hash = crypto.SHA384
	case "RSASSA_PKCS1_v1_5_SHA512":
		isRSA = true
		hash = crypto.SHA512
	case "ECDSA_SHA256":
		isRSA = false
		hash = crypto.SHA256
	case "ECDSA_SHA384":
		isRSA = false
		hash = crypto.SHA384
	case "ECDSA_SHA512":
		isRSA = false
		hash = crypto.SHA512
	default:
		return nil, errors.New("unsupported algorithm")
	}

	engine, ok := svc.cryptoEngines[engineID]
	if !ok {
		return nil, errors.New("engine not found")
	}
	engineInstance := *engine

	signer, err := engineInstance.GetPrivateKeyByID(keyID)
	if err != nil || signer == nil {
		return nil, errors.New("could not get signing key")
	}

	hasher := hash.New()
	hasher.Write(input.Message)
	digest := hasher.Sum(nil)

	var signature []byte
	if isRSA {
		rsaPriv, ok := signer.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not RSA private key")
		}
		// Sign the message using RSA PKCS#1 v1.5
		// Note: RSA signatures are fixed length, depending on the key size.
		// For example, a 2048-bit RSA key will produce a 256-byte signature.
		// The signature is the result of signing the digest with the private key.
		// The signature is returned as a byte slice.
		// The signature is the result of signing the digest with the private key.
		signature, err = rsa.SignPKCS1v15(nil, rsaPriv, hash, digest)
		if err != nil {
			lFunc.Errorf("SignMessage - RSA Sign error: %s", err)
			return nil, err
		}
	} else {
		ecdsaPriv, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not ECDSA private key")
		}
		if ecdsaPriv == nil {
			return nil, errors.New("ecdsa private key is nil")
		}
		if digest == nil {
			return nil, errors.New("digest is nil")
		}
		// Sign the message using ECDSA
		// Note: ECDSA signatures are variable length, depending on the curve used.
		// For example, a P256 curve will produce a 64-byte signature.
		// The signature is the result of signing the digest with the private key.
		// The signature is returned as a byte slice, which is the concatenation of the r and s values.
		r, s, err := ecdsa.Sign(rand.Reader, ecdsaPriv, digest)
		if err != nil {
			lFunc.Errorf("SignMessage - ECDSA Sign error: %s", err)
			return nil, err
		}
		signature = append(r.Bytes(), s.Bytes()...)
	}

	return &models.MessageSignature{
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (svc *KMSServiceBackend) VerifySignature(ctx context.Context, input services.VerifySignInput) (bool, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("VerifySignature struct validation error: %s", err)
		return false, errs.ErrValidateBadRequest
	}

	engineID, keyID, _, err := parsePKCS11ID(input.KeyID)
	if err != nil {
		return false, errors.New("invalid key id format, expected pkcs11:token-id=<engineID>;id=<keyID>;type=<type>")
	}

	var hash crypto.Hash
	var isRSA bool

	switch input.Algorithm {
	case "RSASSA_PKCS1_v1_5_SHA256":
		isRSA = true
		hash = crypto.SHA256
	case "RSASSA_PKCS1_v1_5_SHA384":
		isRSA = true
		hash = crypto.SHA384
	case "RSASSA_PKCS1_v1_5_SHA512":
		isRSA = true
		hash = crypto.SHA512
	case "ECDSA_SHA256":
		isRSA = false
		hash = crypto.SHA256
	case "ECDSA_SHA384":
		isRSA = false
		hash = crypto.SHA384
	case "ECDSA_SHA512":
		isRSA = false
		hash = crypto.SHA512
	default:
		return false, errors.New("unsupported algorithm")
	}

	engine, ok := svc.cryptoEngines[engineID]
	if !ok {
		return false, errors.New("engine not found")
	}
	engineInstance := *engine

	signer, err := engineInstance.GetPrivateKeyByID(keyID)
	if err != nil || signer == nil {
		return false, errors.New("could not get signing key")
	}

	publicKey := signer.Public()

	hasher := hash.New()
	hasher.Write(input.Message)
	digest := hasher.Sum(nil)

	if isRSA {
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return false, errors.New("key is not RSA public key")
		}
		err = rsa.VerifyPKCS1v15(pub, hash, digest, input.Signature)
		if err != nil {
			lFunc.Errorf("VerifySignature - RSA verify error: %s", err)
			return false, nil
		}
		return true, nil
	} else {
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("key is not ECDSA public key")
		}
		// ECDSA signature is r||s, split in half
		sigLen := len(input.Signature)
		if sigLen%2 != 0 || sigLen == 0 {
			return false, errors.New("invalid ECDSA signature length")
		}
		rBytes := input.Signature[:sigLen/2]
		sBytes := input.Signature[sigLen/2:]
		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)
		if !ecdsa.Verify(pub, digest, r, s) {
			return false, nil
		}
		return true, nil
	}
}

func (svc *KMSServiceBackend) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.KeyInfo, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("ImportKeyInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// Validate PEM format
	pemBlock, _ := pem.Decode(input.PrivateKey)
	lFunc.Printf("ImportKey - PEM Block 1: %v", pemBlock.Type)
	lFunc.Printf("ImportKey - PEM Block 2: %v", string(input.PrivateKey))
	if pemBlock == nil || !strings.Contains(string(input.PrivateKey), "-----END "+pemBlock.Type+"-----") {
		lFunc.Errorf("ImportKey - invalid PEM format for private key")
		return nil, errors.New("invalid PEM format for private key")
	}

	// Parse the private key from PEM
	key, err := chelpers.ParsePrivateKey(input.PrivateKey)
	if err != nil {
		lFunc.Errorf("ImportKey - failed to parse private key: %s", err)
		return nil, errors.New("failed to parse private key")
	}

	engine := svc.defaultCryptoEngine
	engineInstance := *engine

	var (
		keyID     string
		signer    crypto.Signer
		algorithm string
		size      string
	)

	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyID, signer, err = engineInstance.ImportRSAPrivateKey(k)
		algorithm = "RSA"
		size = fmt.Sprintf("%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		keyID, signer, err = engineInstance.ImportECDSAPrivateKey(k)
		algorithm = "ECDSA"
		size = fmt.Sprintf("%d", k.Params().BitSize)
	default:
		lFunc.Errorf("ImportKey - unsupported private key type")
		return nil, errors.New("unsupported private key type")
	}
	if err != nil {
		lFunc.Errorf("ImportKey - failed to import private key: %s", err)
		return nil, errors.New("failed to import private key")
	}

	publicKey := signer.Public()
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		lFunc.Errorf("ImportKey - failed to marshal public key: %s", err)
		return nil, errors.New("failed to marshal public key")
	}

	pemBlockPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	base64PEM := base64.StdEncoding.EncodeToString(pemBlockPub)

	return &models.KeyInfo{
		ID:        buildPKCS11ID(svc.defaultCryptoEngineID, keyID, "private"),
		Algorithm: algorithm,
		Size:      size,
		PublicKey: base64PEM,
	}, nil
}
