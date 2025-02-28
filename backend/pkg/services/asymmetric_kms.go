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
	"time"

	asymmetrickms "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/asymmetric_kms"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	core "github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

type AsymmetricKMSServiceBackend struct {
	cryptoEngines         map[string]*cryptoengines.CryptoEngine
	defaultCryptoEngine   *cryptoengines.CryptoEngine
	defaultCryptoEngineID string
	logger                *logrus.Entry
	kmsStore              storage.AsymmetricKMSRepo
}

type AsymmetricKMSServiceBackendBuilder struct {
	Logger        *logrus.Entry
	KMSStore      storage.AsymmetricKMSRepo
	Engines       map[string]*cryptoengines.CryptoEngine
	DefaultEngine string
}

func NewAsymmetricKMSServiceBackend(builder AsymmetricKMSServiceBackendBuilder) core.AsymmetricKMSService {
	return &AsymmetricKMSServiceBackend{
		cryptoEngines:         builder.Engines,
		defaultCryptoEngine:   builder.Engines[builder.DefaultEngine],
		logger:                builder.Logger,
		kmsStore:              builder.KMSStore,
		defaultCryptoEngineID: builder.DefaultEngine,
	}
}

func (s *AsymmetricKMSServiceBackend) getEngine(engineId string) (string, cryptoengines.CryptoEngine, error) {
	id := s.defaultCryptoEngineID
	if engineId != "" {
		_, ok := s.cryptoEngines[engineId]
		if !ok {
			return "", nil, errs.ErrCryptoEngineNotFound
		}
		id = engineId
	}

	engine := s.cryptoEngines[id]

	return id, *engine, nil
}

func (s *AsymmetricKMSServiceBackend) CreateKeyPair(ctx context.Context, spec core.CreateKeyPairInput) (*models.KeyPair, error) {
	lFunc := chelpers.ConfigureLogger(ctx, s.logger)
	engineID, engine, err := s.getEngine(spec.EngineID)
	if err != nil {
		return nil, err
	}

	var kp models.KeyPair
	var signer crypto.Signer

	switch spec.Algorithm {
	case x509.RSA:
		lFunc.Infof("generating RSA key pair with engine %s (%s)", engineID, engine.GetEngineConfig().Type)

		keyID, genSigner, err := engine.CreateRSAPrivateKey(spec.KeySize)
		if err != nil {
			lFunc.Errorf("failed to generate RSA key pair: %s", err)
			return nil, err
		}

		signer = genSigner

		lFunc.Debugf("successfully generated RSA key pair in crypto engine. storing public info in database")

		kp = models.KeyPair{
			KeyID:      keyID,
			Algorithm:  x509.RSA,
			EngineID:   engineID,
			CreatedAt:  time.Now(),
			Imported:   false,
			Exported:   false,
			HasPrivate: true,
			KeySize:    spec.KeySize,
		}

	case x509.ECDSA:
		lFunc.Infof("generating ECDSA key pair with engine %s (%s)", engineID, engine.GetEngineConfig().Type)
		var curve elliptic.Curve
		switch spec.KeySize {
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

		keyID, genSigner, err := engine.CreateECDSAPrivateKey(curve)
		if err != nil {
			lFunc.Errorf("failed to generate ECDSA key pair: %s", err)
			return nil, err
		}

		signer = genSigner

		lFunc.Debugf("successfully generated ECDSA key pair in crypto engine. storing public info in database")

		kp = models.KeyPair{
			KeyID:      keyID,
			Algorithm:  x509.ECDSA,
			EngineID:   engineID,
			CreatedAt:  time.Now(),
			Imported:   false,
			Exported:   false,
			HasPrivate: true,
			KeySize:    spec.KeySize,
		}
	default:
		return nil, errors.New("unsupported algorithm")
	}

	kp.PublicKey = models.X509PublicKey{
		Key: signer.Public(),
	}

	_, err = s.kmsStore.Insert(ctx, &kp)
	if err != nil {
		lFunc.Errorf("failed to store key pair in database: %s", err)
		return nil, err
	}

	return &kp, nil
}

func (s *AsymmetricKMSServiceBackend) ImportKeyPair(ctx context.Context, input core.ImportKeyPairInput) (*models.KeyPair, error) {
	lFunc := chelpers.ConfigureLogger(ctx, s.logger)
	engineID, engine, err := s.getEngine(input.EngineID)
	if err != nil {
		return nil, err
	}

	kp := models.KeyPair{
		EngineID:  engineID,
		Imported:  true,
		Exported:  false,
		CreatedAt: time.Now(),
	}

	var pubKey any

	if input.PrivateKey.Key != nil {
		kp.HasPrivate = true

		switch key := input.PrivateKey.Key.(type) {
		case *rsa.PrivateKey:
			_, _, err = engine.ImportRSAPrivateKey(key)
			pubKey = key.Public()
		case *ecdsa.PrivateKey:
			_, _, err = engine.ImportECDSAPrivateKey(key)
			pubKey = key.Public()
		}

		if err != nil {
			lFunc.Errorf("failed to import private key: %s", err)
			return nil, err
		}
	} else {
		pubKey = input.PublicKey.Key
	}

	sce := software.NewSoftwareCryptoEngine(lFunc)
	kid, err := sce.EncodePKIXPublicKeyDigest(pubKey)
	if err != nil {
		lFunc.Errorf("failed to encode public key digest: %s", err)
		return nil, err
	}

	switch pubKey.(type) {
	case *rsa.PublicKey:
		kp.Algorithm = x509.RSA
		kp.KeySize = pubKey.(*rsa.PublicKey).Size() * 8
		kp.KeyStrength = asymmetrickms.KeyStrengthBuilder(models.KeyType(kp.Algorithm), kp.KeySize)
	case *ecdsa.PublicKey:
		kp.Algorithm = x509.ECDSA
		kp.KeySize = pubKey.(*ecdsa.PublicKey).Params().BitSize
	}

	_, err = s.kmsStore.Insert(ctx, &kp)
	if err != nil {
		lFunc.Errorf("failed to store key pair in database: %s", err)
		return nil, err
	}

	kp.KeyID = kid

	return &kp, nil
}

func (s *AsymmetricKMSServiceBackend) ExportPrivateKey(ctx context.Context, input core.ExportPrivateKeyInput) ([]byte, error) {
	return nil, nil
}

func (s *AsymmetricKMSServiceBackend) GetKeyPair(ctx context.Context, input core.GetKeyPairInput) (*models.KeyPair, error) {
	lFunc := chelpers.ConfigureLogger(ctx, s.logger)
	exists, kp, err := s.kmsStore.SelectExists(ctx, input.KeyID)
	if err != nil {
		lFunc.Errorf("failed to get key pair from database: %s", err)
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("key pair with ID %s not found", input.KeyID)
	}

	return kp, nil
}

func (s *AsymmetricKMSServiceBackend) DeleteKeyPair(ctx context.Context, input core.DeleteKeyPairInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, s.logger)
	kp, err := s.GetKeyPair(ctx, core.GetKeyPairInput{
		KeyID: input.KeyID,
	})
	if err != nil {
		lFunc.Errorf("failed to get key pair from database: %s", err)
		return err
	}

	_, engine, err := s.getEngine(kp.EngineID)
	if err != nil {
		lFunc.Errorf("failed to get crypto engine: %s", err)
		return err
	}

	err = engine.DeleteKey(input.KeyID)
	if err != nil {
		lFunc.Errorf("failed to delete key pair from crypto engine: %s", err)
		return err
	}

	err = s.kmsStore.Delete(ctx, input.KeyID)
	if err != nil {
		lFunc.Errorf("failed to delete key pair from database: %s", err)
		return err
	}

	return err
}

func (s *AsymmetricKMSServiceBackend) GetKeyPairs(ctx context.Context, input core.GetKeyPairsInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, s.logger)

	next, err := s.kmsStore.SelectAll(ctx, storage.StorageListRequest[models.KeyPair]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     map[string]interface{}{},
	})
	if err != nil {
		lFunc.Errorf("failed to list key pairs from database: %s", err)
		return "", err
	}

	return next, nil
}

func (s *AsymmetricKMSServiceBackend) Stats(ctx context.Context) (models.KMSStats, error) {
	return models.KMSStats{
		TotalKeyPairs:     0,
		KeyPairsPerEngine: map[string]int{},
	}, nil
}

func (s *AsymmetricKMSServiceBackend) Sign(ctx context.Context, input core.KMSSignInput) ([]byte, error) {
	lFunc := chelpers.ConfigureLogger(ctx, s.logger)
	kp, err := s.GetKeyPair(ctx, core.GetKeyPairInput{
		KeyID: input.KeyID,
	})
	if err != nil {
		lFunc.Errorf("failed to get key pair from database: %s", err)
		return nil, err
	}

	_, engine, err := s.getEngine(kp.EngineID)
	if err != nil {
		lFunc.Errorf("failed to get crypto engine: %s", err)
		return nil, err
	}

	signer, err := engine.GetPrivateKeyByID(input.KeyID)
	if err != nil {
		lFunc.Errorf("failed to get private key from crypto engine: %s", err)
		return nil, err
	}

	lFunc.Infof("signing message with key %s", input.KeyID)

	switch kp.Algorithm {
	case x509.ECDSA:
		var digest []byte
		var hashFunc crypto.Hash
		var h hash.Hash

		switch input.SignatureAlgorithm {
		case x509.ECDSAWithSHA256:
			h = sha256.New()
			hashFunc = crypto.SHA256
		case x509.ECDSAWithSHA384:
			h = sha512.New384()
			hashFunc = crypto.SHA384
		case x509.ECDSAWithSHA512:
			h = sha512.New()
			hashFunc = crypto.SHA512
		default:
			return nil, errs.ErrEngineAlgNotSupported
		}

		if input.MessageType == models.Raw {
			h.Write(input.Message)
			digest = h.Sum(nil)
		} else {
			digest = input.Message
		}

		signature, err := signer.Sign(rand.Reader, digest, hashFunc)
		if err != nil {
			return nil, err
		}

		return signature, nil
	case x509.RSA:
		var digest []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		switch input.SignatureAlgorithm {
		case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
			h = sha256.New()
			hashFunc = crypto.SHA256
		case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
			h = sha512.New384()
			hashFunc = crypto.SHA384
		case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
			h = sha512.New()
			hashFunc = crypto.SHA512
		default:
			return nil, errs.ErrEngineAlgNotSupported
		}

		if input.MessageType == models.Raw {
			h.Write(input.Message)
			digest = h.Sum(nil)
		} else {
			digest = input.Message
		}

		switch input.SignatureAlgorithm {
		case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			signature, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashFunc,
			})
			if err != nil {
				return nil, err
			}

			return signature, nil
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
			signature, err := signer.Sign(rand.Reader, digest, hashFunc)
			if err != nil {
				return nil, err
			}

			return signature, nil
		default:
			return nil, errs.ErrEngineAlgNotSupported
		}
	default:
		return nil, fmt.Errorf("key pair algorithm %s not supported", kp.Algorithm)
	}
}

func (s *AsymmetricKMSServiceBackend) Verify(ctx context.Context, input core.VerifyInput) (bool, error) {
	lFunc := chelpers.ConfigureLogger(ctx, s.logger)
	kp, err := s.GetKeyPair(ctx, core.GetKeyPairInput{
		KeyID: input.KeyID,
	})
	if err != nil {
		lFunc.Errorf("failed to get key pair from database: %s", err)
		return false, err
	}

	lFunc.Infof("verifying signature with key %s", input.KeyID)

	switch kp.Algorithm {
	case x509.ECDSA:
		var digest []byte
		var h hash.Hash

		switch input.SignatureAlgorithm {
		case x509.ECDSAWithSHA256:
			h = sha256.New()
		case x509.ECDSAWithSHA384:
			h = sha512.New384()
		case x509.ECDSAWithSHA512:
			h = sha512.New()
		default:
			return false, errs.ErrEngineAlgNotSupported
		}

		pubKey, ok := kp.PublicKey.Key.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("public key is not ECDSA")
		}

		if input.MessageType == models.Raw {
			h.Write(input.Message)
			digest = h.Sum(nil)
		} else {
			digest = input.Message
		}

		return ecdsa.VerifyASN1(pubKey, digest, input.Signature), nil
	case x509.RSA:
		var digest []byte
		var hashFunc crypto.Hash
		var h hash.Hash

		switch input.SignatureAlgorithm {
		case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
			h = sha256.New()
			hashFunc = crypto.SHA256
		case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
			h = sha512.New384()
			hashFunc = crypto.SHA384
		case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
			h = sha512.New()
			hashFunc = crypto.SHA512
		default:
			return false, errs.ErrEngineAlgNotSupported
		}

		pubKey, ok := kp.PublicKey.Key.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("public key is not ECDSA")
		}

		if input.MessageType == models.Raw {
			h.Write(input.Message)
			digest = h.Sum(nil)
		} else {
			digest = input.Message
		}

		switch input.SignatureAlgorithm {
		case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			err = rsa.VerifyPSS(pubKey, hashFunc, digest, input.Signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashFunc,
			})
			if err != nil {
				return false, err
			}

			return true, nil
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
			err = rsa.VerifyPKCS1v15(pubKey, hashFunc, digest, input.Signature)
			if err != nil {
				return false, err
			}

			return true, nil
		default:
			return false, errs.ErrEngineAlgNotSupported
		}
	default:
		return false, fmt.Errorf("key pair algorithm %s not supported", kp.Algorithm)
	}
}
