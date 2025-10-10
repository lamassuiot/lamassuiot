package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/service/kms"
	"github.com/sirupsen/logrus"
)

type caSignerImpl struct {
	sdk kms.KMSService
	ca  *models.CACertificate
	ctx context.Context
}

func NewCASigner(ctx context.Context, ca *models.CACertificate, kmsSDK kms.KMSService) crypto.Signer {
	return &caSignerImpl{
		ctx: ctx,
		sdk: kmsSDK,
		ca:  ca,
	}
}

func (s *caSignerImpl) Public() crypto.PublicKey {
	return s.ca.Certificate.Certificate.PublicKey
}

func (s *caSignerImpl) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signAlg := "RSASSA_PKCS1_V1_5_SHA_256"
	caKeyAlg := s.ca.Certificate.Certificate.PublicKeyAlgorithm
	caHashFunc := opts.HashFunc()
	caHashSize := caHashFunc.Size() * 8
	switch caKeyAlg {
	case x509.ECDSA:
		signAlg = fmt.Sprintf("ECDSA_SHA_%d", caHashSize)
	case x509.RSA:
		signAlg = fmt.Sprintf("RSASSA_PKCS1_V1_5_SHA_%d", caHashSize)
	default:
		logrus.Warnf("using default %s sign alg for client. '%s' no match", signAlg, caKeyAlg)
	}

	msg, err := s.sdk.SignMessage(s.ctx, kms.SignMessageInput{
		KeyID:       s.ca.Certificate.SubjectKeyID,
		Algorithm:   signAlg,
		Message:     digest,
		MessageType: kms.SignMessageTypeRaw,
	})
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
