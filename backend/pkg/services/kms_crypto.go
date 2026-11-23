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

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/kmip"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/software"
)

// kmipAlgorithm maps the algorithm the KMS stores for a key to its KMIP Cryptographic Algorithm.
func kmipAlgorithm(algorithm string) (kmip.CryptographicAlgorithm, bool) {
	switch algorithm {
	case "RSA":
		return kmip.RSA, true
	case "ECDSA":
		return kmip.ECDSA, true
	default:
		return 0, false
	}
}

// keyRef is the reference the engine of a stored private key knows it by.
func keyRef(key *models.Key) cryptoengines.KeyRef {
	alg, _ := kmipAlgorithm(key.Algorithm)
	return cryptoengines.KeyRef{KeyID: key.KeyID, ObjectType: kmip.PrivateKey, Algorithm: alg, Length: key.Size}
}

// loadSigner loads the private key of key from its engine.
func (svc *KMSServiceBackend) loadSigner(ctx context.Context, key *models.Key) (cryptoengines.Signer, error) {
	backend, ok := svc.backends[key.EngineID]
	if !ok {
		return nil, errors.New("engine not found")
	}

	handle, err := backend.Load(ctx, keyRef(key))
	if err != nil || handle == nil {
		return nil, errors.New("could not get signing key")
	}
	signer, ok := handle.(cryptoengines.Signer)
	if !ok {
		return nil, errors.New("could not get signing key")
	}
	return signer, nil
}

// parseStoredPublicKey decodes a public key as the KMS stores it: base64 of its PEM encoding.
func parseStoredPublicKey(stored string) (crypto.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(der)
	if block == nil {
		return nil, errors.New("stored public key is not PEM")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// keyOperation is what SignMessage and VerifySignature share: the addressed key and the parsed algorithm.
type keyOperation struct {
	Key   *models.Key
	Hash  crypto.Hash
	IsRSA bool
	IsPSS bool
}

func (svc *KMSServiceBackend) resolveKeyOperation(ctx context.Context, identifier, algorithm, operationName string, input any) (*keyOperation, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	if err := kmsValidator.Struct(input); err != nil {
		lFunc.Errorf("%s struct validation error: %s", operationName, err)
		return nil, errs.ErrValidateBadRequest
	}

	key, err := svc.GetKey(ctx, services.GetKeyInput{Identifier: identifier})
	if err != nil {
		return nil, err
	}

	hash, isRSA, isPSS, err := parseAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	return &keyOperation{Key: key, Hash: hash, IsRSA: isRSA, IsPSS: isPSS}, nil
}

func (svc *KMSServiceBackend) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	op, err := svc.resolveKeyOperation(ctx, input.Identifier, input.Algorithm, "SignMessage", input)
	if err != nil {
		return nil, err
	}

	signer, err := svc.loadSigner(ctx, op.Key)
	if err != nil {
		return nil, err
	}

	digest, err := calculateDigest(op.Hash, input.MessageType, input.Message)
	if err != nil {
		lFunc.Errorf("calculate digest error: %s", err)
		return nil, err
	}
	if digest == nil {
		return nil, errors.New("digest is nil")
	}

	var opts crypto.SignerOpts = op.Hash
	if op.IsRSA && op.IsPSS {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: op.Hash}
	}

	signature, err := signer.Sign(software.NewLamassuEntropy(ctx), digest, opts)
	if err != nil {
		lFunc.Errorf("%s sign error: %s", input.Algorithm, err)
		return nil, err
	}

	return &models.MessageSignature{Signature: signature}, nil
}

// VerifySignature verifies with the stored public key of the addressed key: KMIP's Signature Verify works on the
// public part, so it needs no engine and also works for keys whose private part the KMS does not hold.
func (svc *KMSServiceBackend) VerifySignature(ctx context.Context, input services.VerifySignInput) (*models.MessageValidation, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	op, err := svc.resolveKeyOperation(ctx, input.Identifier, input.Algorithm, "VerifySignature", input)
	if err != nil {
		return nil, err
	}

	publicKey, err := parseStoredPublicKey(op.Key.PublicKey)
	if err != nil {
		lFunc.Errorf("could not parse the stored public key of key %s: %s", op.Key.KeyID, err)
		return nil, errors.New("could not read the public key")
	}

	digest, err := calculateDigest(op.Hash, input.MessageType, input.Message)
	if err != nil {
		lFunc.Errorf("calculate digest error: %s", err)
		return nil, err
	}

	if op.IsRSA {
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("key is not RSA key")
		}
		if op.IsPSS {
			err = rsa.VerifyPSS(pub, op.Hash, digest, input.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: op.Hash})
		} else {
			err = rsa.VerifyPKCS1v15(pub, op.Hash, digest, input.Signature)
		}
		if err != nil {
			lFunc.Errorf("RSA verify error: %s", err)
			return &models.MessageValidation{Valid: false}, nil
		}
		return &models.MessageValidation{Valid: true}, nil
	}

	pub, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not ECDSA key")
	}
	return &models.MessageValidation{Valid: ecdsa.VerifyASN1(pub, digest, input.Signature)}, nil
}
