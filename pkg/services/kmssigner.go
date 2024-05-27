package services

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
)

type remoteKmsSigner struct {
	sdk      KMSService
	kid      string
	engineId string
	pubKey   crypto.PublicKey
	key      *models.AsymmetricCryptoKey
}

func NewKMSCryptoSigner(engineID, kid string, kmsSDK KMSService) (crypto.Signer, error) {
	key, err := kmsSDK.GetKey(context.Background(), GetKeyInput{
		EngineID: engineID,
		KeyID:    kid,
	})
	if err != nil {
		return nil, err
	}

	pubKey, err := helpers.PublicKeyPEMToCryptoKey(key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &remoteKmsSigner{
		sdk:      kmsSDK,
		kid:      kid,
		engineId: engineID,
		pubKey:   pubKey,
		key:      key,
	}, nil
}

func (s *remoteKmsSigner) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *remoteKmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	baseSignAlg := ""
	if s.key.Algorithm == models.KeyType(x509.ECDSA) {
		baseSignAlg = "ECDSA"
	} else if s.key.Algorithm == models.KeyType(x509.RSA) {
		if _, ok := opts.(*rsa.PSSOptions); ok {
			baseSignAlg = "RSASSA_PSS"
		} else {
			baseSignAlg = "RSASSA_PKCS1_V1_5"
		}
	}

	signAlg := fmt.Sprintf("%s_SHA_%d", baseSignAlg, opts.HashFunc().Size()*8)

	return s.sdk.Sign(context.Background(), SignInput{
		EngineID:         s.engineId,
		KeyID:            s.kid,
		Message:          digest,
		MessageType:      models.Hashed,
		SigningAlgorithm: signAlg,
	})
}
