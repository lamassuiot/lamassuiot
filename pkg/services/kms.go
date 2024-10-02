package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/sirupsen/logrus"
)

type KMSService interface {
	GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error)

	CreatePrivateKey(ctx context.Context, input CreatePrivateKeyInput) (*models.AsymmetricCryptoKey, error)
	ImportPrivateKey(ctx context.Context, input ImportPrivateKeyInput) (*models.AsymmetricCryptoKey, error)
	GetKey(ctx context.Context, input GetKeyInput) (*models.AsymmetricCryptoKey, error)

	Sign(ctx context.Context, input SignInput) (signature []byte, err error)
	Verify(ctx context.Context, input VerifyInput) (bool, error)
}

type CryptoEngineMiddleware func(KMSService) KMSService

type Engine struct {
	Default bool
	Service cryptoengines.CryptoEngine
}

type KMSServiceBackend struct {
	logger                *logrus.Entry
	service               KMSService
	cryptoEngines         map[string]*cryptoengines.CryptoEngine
	defaultCryptoEngine   *cryptoengines.CryptoEngine
	defaultCryptoEngineID string
}

type KMSServiceBuilder struct {
	Logger        *logrus.Entry
	CryptoEngines map[string]*Engine
}

func NewKMSService(builder KMSServiceBuilder) (KMSService, error) {
	validate = validator.New()

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
		logger:                builder.Logger,
		cryptoEngines:         engines,
		defaultCryptoEngine:   defaultCryptoEngine,
		defaultCryptoEngineID: defaultCryptoEngineID,
	}

	svc.service = &svc

	return &svc, nil
}

func (svc *KMSServiceBackend) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

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

	lFunc.Tracef("got %d engines", len(info))
	return info, nil
}

func (svc *KMSServiceBackend) SetService(service KMSService) {
	svc.service = service
}

type CreatePrivateKeyInput struct {
	EngineID     string
	KeyAlgorithm models.KeyType
	KeySize      int
}

func (svc *KMSServiceBackend) CreatePrivateKey(ctx context.Context, input CreatePrivateKeyInput) (*models.AsymmetricCryptoKey, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	enginePtr, err := svc.GetEngine(ctx, input.EngineID)
	if err != nil {
		lFunc.Errorf(err.Error())
		return nil, err
	}

	lFunc.Debugf("successfully got engine %s", input.EngineID)
	hash := sha256.New()
	hash.Write([]byte(uuid.NewString()))
	kid := fmt.Sprintf("%x", hash.Sum(nil))

	engine := *enginePtr
	if input.KeyAlgorithm == models.KeyType(x509.RSA) {
		lFunc.Debugf("requesting crypto engine instance for RSA key '%s' generation of size: %d", kid, input.KeySize)
		_, err = engine.CreateRSAPrivateKey(input.KeySize, kid)
		if err != nil {
			lFunc.Errorf("crypto engine instance failed while generating RSA key: %s", err)
			return nil, err
		}
		lFunc.Debugf("crypto engine successfully generated RSA key")
	} else {
		var curve elliptic.Curve
		switch input.KeySize {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported key size for ECDSA key")
		}

		lFunc.Debugf("requesting crypto engine instance for ECDSA key '%s' generation of size: %d", kid, input.KeySize)
		_, err = engine.CreateECDSAPrivateKey(curve, kid)
		if err != nil {
			lFunc.Errorf("crypto engine instance failed while generating ECDSA key: %s", err)
			return nil, err
		}
		lFunc.Debugf("crypto engine successfully generated ECDSA key")
	}

	engineID := svc.defaultCryptoEngineID
	if input.EngineID != "" {
		engineID = input.EngineID
	}

	return svc.GetKey(ctx, GetKeyInput{
		EngineID: engineID,
		KeyID:    kid,
	})
}

type ImportPrivateKeyInput struct {
	EngineID string
	KeyType  models.KeyType
	RSAKey   *rsa.PrivateKey
	ECKey    *ecdsa.PrivateKey
}

func (svc *KMSServiceBackend) ImportPrivateKey(ctx context.Context, input ImportPrivateKeyInput) (*models.AsymmetricCryptoKey, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)
	enginePtr, err := svc.GetEngine(ctx, input.EngineID)
	if err != nil {
		lFunc.Errorf(err.Error())
		return nil, err
	}

	lFunc.Debugf("successfully got engine %s", input.EngineID)
	engine := *enginePtr

	hash := sha256.New()
	hash.Write([]byte(uuid.NewString()))
	kid := fmt.Sprintf("%x", hash.Sum(nil))

	if input.KeyType == models.KeyType(x509.RSA) {
		_, err = engine.ImportRSAPrivateKey(input.RSAKey, kid)
		if err != nil {
			lFunc.Errorf(err.Error())
			return nil, err
		}
	} else if input.KeyType == models.KeyType(x509.ECDSA) {
		_, err = engine.ImportECDSAPrivateKey(input.ECKey, kid)
		if err != nil {
			lFunc.Errorf(err.Error())
			return nil, err
		}
	} else {
		err = fmt.Errorf("invalid key type")
		lFunc.Errorf(err.Error())
		return nil, err
	}

	engineID := svc.defaultCryptoEngineID
	if input.EngineID != "" {
		engineID = input.EngineID
	}
	return svc.GetKey(ctx, GetKeyInput{
		EngineID: engineID,
		KeyID:    kid,
	})
}

type GetKeyInput struct {
	EngineID string
	KeyID    string
}

func (svc *KMSServiceBackend) GetKey(ctx context.Context, input GetKeyInput) (*models.AsymmetricCryptoKey, error) {
	var err error
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	getKeyByEngine := func(engineID string) (crypto.Signer, error) {
		enginePtr, err := svc.GetEngine(ctx, input.EngineID)
		if err != nil {
			lFunc.Errorf(err.Error())
			return nil, err
		}

		lFunc.Debugf("successfully got engine %s", input.EngineID)
		engine := *enginePtr

		signer, err := engine.GetPrivateKeyByID(input.KeyID)
		if err != nil {
			lFunc.Errorf(err.Error())
			return nil, err
		}

		return signer, nil
	}

	var signer crypto.Signer
	if input.EngineID != "" {
		signer, err = getKeyByEngine(input.EngineID)
		if err != nil {
			return nil, err
		}
	} else {
		for engineID, _ := range svc.cryptoEngines {
			signer, err = getKeyByEngine(engineID)
			if err != nil {
				continue
			} else {
				break
			}
		}

		if signer == nil {
			return nil, fmt.Errorf("could not find key in any engine")
		}
	}

	keyType := x509.UnknownPublicKeyAlgorithm
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		keyType = x509.RSA
	case *ecdsa.PublicKey:
		keyType = x509.ECDSA
	}

	pubKey, err := helpers.PublicKeyToPEM(signer.Public())
	if err != nil {
		lFunc.Errorf(err.Error())
		return nil, err
	}

	return &models.AsymmetricCryptoKey{
		KeyID:     input.KeyID,
		EngineID:  input.EngineID,
		PublicKey: pubKey,
		Algorithm: models.KeyType(keyType),
	}, nil
}

type SignInput struct {
	EngineID         string
	KeyID            string
	Message          []byte
	MessageType      models.SignMessageType
	SigningAlgorithm string
}

func (svc *KMSServiceBackend) Sign(ctx context.Context, input SignInput) (signature []byte, err error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	enginePtr, err := svc.GetEngine(ctx, input.EngineID)
	if err != nil {
		lFunc.Errorf(err.Error())
		return nil, err
	}

	lFunc.Debugf("successfully got engine %s", input.EngineID)

	engine := *enginePtr
	signer, err := engine.GetPrivateKeyByID(input.KeyID)
	if err != nil {
		lFunc.Errorf(err.Error())
		return nil, err
	}

	lFunc.Debugf("successfully got key signer")

	var digest []byte
	var hashFunc crypto.Hash
	var h hash.Hash
	var signOpts crypto.SignerOpts

	if strings.HasSuffix(input.SigningAlgorithm, "SHA_256") {
		h = sha256.New()
		hashFunc = crypto.SHA256
	} else if strings.HasSuffix(input.SigningAlgorithm, "SHA_384") {
		h = sha512.New384()
		hashFunc = crypto.SHA384
	} else if strings.HasSuffix(input.SigningAlgorithm, "SHA_512") {
		h = sha512.New()
		hashFunc = crypto.SHA512
	} else {
		lFunc.Errorf(errs.ErrEngineAlgNotSupported.Error())
		return nil, errs.ErrEngineAlgNotSupported
	}

	if input.MessageType == models.Raw {
		h.Write(input.Message)
		digest = h.Sum(nil)
	} else {
		digest = input.Message
		if err != nil {
			lFunc.Errorf(err.Error())
			return nil, err
		}
	}

	if strings.HasPrefix(input.SigningAlgorithm, "RSASSA_PSS") {
		var saltLength int
		switch hashFunc {
		case crypto.SHA256:
			saltLength = 32
		case crypto.SHA384:
			saltLength = 48
		case crypto.SHA512:
			saltLength = 64
		}

		signOpts = &rsa.PSSOptions{
			SaltLength: saltLength,
			Hash:       hashFunc,
		}
	} else {
		signOpts = hashFunc
	}

	signature, err = signer.Sign(rand.Reader, digest, signOpts)
	if err != nil {
		lFunc.Errorf(err.Error())
		return nil, err
	}

	lFunc.Debugf("successfully generated signature")
	lFunc.Tracef("signature is (bytes encoded to string): %s", string(signature))
	return signature, nil
}

type VerifyInput struct {
	EngineID         string
	KeyID            string
	Signature        []byte                 `validate:"required"`
	Message          []byte                 `validate:"required"`
	MessageType      models.SignMessageType `validate:"required"`
	SigningAlgorithm string                 `validate:"required"`
}

func (svc *KMSServiceBackend) Verify(ctx context.Context, input VerifyInput) (bool, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	enginePtr, err := svc.GetEngine(ctx, input.EngineID)
	if err != nil {
		lFunc.Errorf(err.Error())
		return false, err
	}

	lFunc.Debugf("successfully got engine %s", input.EngineID)

	engine := *enginePtr
	signer, err := engine.GetPrivateKeyByID(input.KeyID)
	if err != nil {
		lFunc.Errorf(err.Error())
		return false, err
	}

	lFunc.Debugf("successfully got key signer")
	var digest []byte
	var hashFunc crypto.Hash
	var h hash.Hash

	if strings.HasSuffix(input.SigningAlgorithm, "SHA_256") {
		h = sha256.New()
		hashFunc = crypto.SHA256
	} else if strings.HasSuffix(input.SigningAlgorithm, "SHA_384") {
		h = sha512.New384()
		hashFunc = crypto.SHA384
	} else if strings.HasSuffix(input.SigningAlgorithm, "SHA_512") {
		h = sha512.New()
		hashFunc = crypto.SHA512
	} else {
		lFunc.Errorf(errs.ErrEngineAlgNotSupported.Error())
		return false, errs.ErrEngineAlgNotSupported
	}

	if input.MessageType == models.Raw {
		h.Write(input.Message)
		digest = h.Sum(nil)
	} else {
		digest = input.Message
		if err != nil {
			lFunc.Errorf(err.Error())
			return false, err
		}
	}

	if strings.HasPrefix(input.SigningAlgorithm, "ECDSA") {
		ecdsaKey, _ := signer.Public().(*ecdsa.PublicKey)
		return ecdsa.VerifyASN1(ecdsaKey, digest, input.Signature), nil
	} else if strings.HasPrefix(input.SigningAlgorithm, "RSASSA") {
		rsaPubKey, _ := signer.Public().(*rsa.PublicKey)
		if strings.HasPrefix(input.SigningAlgorithm, "RSASSA_PSS") {
			var saltLength int
			switch hashFunc {
			case crypto.SHA256:
				saltLength = 32
			case crypto.SHA384:
				saltLength = 48
			case crypto.SHA512:
				saltLength = 64
			}
			err = rsa.VerifyPSS(rsaPubKey, hashFunc, digest, input.Signature, &rsa.PSSOptions{
				SaltLength: saltLength,
				Hash:       hashFunc,
			})
			if err != nil {
				return false, err
			}
			return true, nil
		} else if strings.HasPrefix(input.SigningAlgorithm, "RSASSA_PKCS1_V1_5") {
			err = rsa.VerifyPKCS1v15(rsaPubKey, hashFunc, digest, input.Signature)
			if err != nil {
				return false, err
			}
			return true, nil
		} else {
			return false, errs.ErrEngineAlgNotSupported
		}
	} else {
		return false, errs.ErrEngineAlgNotSupported
	}
}

func (svc *KMSServiceBackend) GetEngineConfig(ctx context.Context, engineID string) (*models.CryptoEngineInfo, error) {
	rengine, err := svc.GetEngine(ctx, engineID)
	if err != nil {
		return nil, err
	}

	engine := *rengine
	conf := engine.GetEngineConfig()
	return &conf, nil
}

func (svc *KMSServiceBackend) GetEngine(ctx context.Context, engineID string) (*cryptoengines.CryptoEngine, error) {
	if engineID == "" {
		return svc.defaultCryptoEngine, nil
	} else if engine, hasEngine := svc.cryptoEngines[engineID]; hasEngine {
		return engine, nil
	} else {
		return nil, fmt.Errorf("engine does not exist")
	}
}
