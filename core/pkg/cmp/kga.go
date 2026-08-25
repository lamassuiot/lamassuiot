package cmp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/cms"
)

// oidExtendedKeyUsageCMKGA is id-kp-cmKGA (RFC 9483 / RFC 4210bis): the
// extended key usage a KGA signer certificate MUST carry.
var oidExtendedKeyUsageCMKGA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 32}

// KGADecryptOptions controls validation and decryption of a central-key-
// generation response. Roots may be nil to verify the CMS signature without
// performing certificate-chain validation; production clients should provide it.
type KGADecryptOptions struct {
	Recipient   crypto.Signer
	Roots       *x509.CertPool
	CurrentTime time.Time
}

// KGAResponse contains the certificate and private key delivered by an
// RFC 9483 central-key-generation response.
type KGAResponse struct {
	CertReqID   int
	Status      PKIStatusInfo
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	KGASigner   *x509.Certificate
}

// DecodeKGAResponse decodes an ip, cp, or kup message, decrypts its CMS key
// package with the request protection key, validates the KGA signature, and
// returns the issued certificate and generated private key.
//
// The CMP message envelope (CertRepMessage → CertifiedKeyPair) is decoded here;
// the embedded CMS EnvelopedData/SignedData is opened by the cms package.
func DecodeKGAResponse(message ParsedMessage, options KGADecryptOptions) (KGAResponse, error) {
	if message.Body.Type != BodyIP && message.Body.Type != BodyCP && message.Body.Type != BodyKUP {
		return KGAResponse{}, fmt.Errorf("body type %d is not a certificate response", message.Body.Type)
	}
	if options.Recipient == nil {
		return KGAResponse{}, fmt.Errorf("KGA recipient private key is required")
	}
	var certRep ServerCertRepMessage
	if rest, err := asn1.Unmarshal(message.Body.DER, &certRep); err != nil || len(rest) != 0 {
		if err == nil {
			err = fmt.Errorf("%d trailing bytes", len(rest))
		}
		return KGAResponse{}, fmt.Errorf("decode CertRepMessage: %w", err)
	}
	if len(certRep.Responses) != 1 {
		return KGAResponse{}, fmt.Errorf("KGA response must contain exactly one CertResponse, got %d", len(certRep.Responses))
	}
	response := certRep.Responses[0]
	result := KGAResponse{CertReqID: response.CertReqID, Status: response.Status}
	if response.Status.Status != StatusAccepted && response.Status.Status != StatusGrantedWithMods {
		return result, fmt.Errorf("KGA enrollment returned PKI status %d", response.Status.Status)
	}
	certDER, envelopeDER, err := decodeKGACertifiedKeyPair(response.CertifiedKeyPair)
	if err != nil {
		return result, err
	}
	result.Certificate, err = x509.ParseCertificate(certDER)
	if err != nil {
		return result, fmt.Errorf("parse KGA-issued certificate: %w", err)
	}

	// Open the EnvelopedData with the request protection key; its content is the
	// KGA-signed SignedData.
	signedDataDER, contentType, err := cms.DecryptEnvelopedData(envelopeDER, options.Recipient, message.ExtraCerts)
	if err != nil {
		return result, err
	}
	if !contentType.Equal(cms.OIDSignedData()) {
		return result, fmt.Errorf("KGA encrypted content type is %s, want signedData", contentType)
	}

	// Verify the KGA SignedData: chain to a trust anchor (when Roots is set),
	// require the id-kp-cmKGA EKU, and check the mandatory signed attributes and
	// signature.
	verified, err := cms.VerifySignedData(signedDataDER, message.ExtraCerts, cms.VerifyOptions{
		Roots:        options.Roots,
		CurrentTime:  options.CurrentTime,
		RequiredEKUs: []asn1.ObjectIdentifier{oidExtendedKeyUsageCMKGA},
	})
	if err != nil {
		return result, err
	}
	if !verified.EContentType.Equal(cms.OIDKeyPackage()) {
		return result, fmt.Errorf("KGA SignedData contains unexpected content type %s", verified.EContentType)
	}
	result.KGASigner = verified.SignerCert
	result.PrivateKey, err = cms.ParseAsymmetricKeyPackage(verified.EContent)
	if err != nil {
		return result, err
	}
	if err := matchKGAKeyAndCertificate(result.PrivateKey, result.Certificate); err != nil {
		return result, err
	}
	return result, nil
}

func decodeKGACertifiedKeyPair(raw asn1.RawValue) ([]byte, []byte, error) {
	if len(raw.FullBytes) == 0 {
		return nil, nil, fmt.Errorf("KGA response has no CertifiedKeyPair")
	}
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(raw.FullBytes, &sequence); err != nil {
		return nil, nil, fmt.Errorf("decode CertifiedKeyPair: %w", err)
	} else if len(rest) != 0 {
		return nil, nil, fmt.Errorf("decode CertifiedKeyPair: %d trailing bytes", len(rest))
	}
	var certChoice asn1.RawValue
	rest, err := asn1.Unmarshal(sequence.Bytes, &certChoice)
	if err != nil || certChoice.Class != asn1.ClassContextSpecific || certChoice.Tag != 0 {
		return nil, nil, fmt.Errorf("KGA CertOrEncCert must contain a plain certificate")
	}
	var privateKey asn1.RawValue
	if tail, err := asn1.Unmarshal(rest, &privateKey); err != nil {
		return nil, nil, fmt.Errorf("decode CertifiedKeyPair.privateKey: %w", err)
	} else if len(tail) != 0 {
		return nil, nil, fmt.Errorf("decode CertifiedKeyPair.privateKey: %d trailing bytes", len(tail))
	}
	if privateKey.Class != asn1.ClassContextSpecific || privateKey.Tag != 0 {
		return nil, nil, fmt.Errorf("KGA CertifiedKeyPair has no privateKey field")
	}
	var encryptedKey asn1.RawValue
	if tail, err := asn1.Unmarshal(privateKey.Bytes, &encryptedKey); err != nil {
		return nil, nil, fmt.Errorf("decode EncryptedKey: %w", err)
	} else if len(tail) != 0 {
		return nil, nil, fmt.Errorf("decode EncryptedKey: %d trailing bytes", len(tail))
	}
	if encryptedKey.Class != asn1.ClassContextSpecific || encryptedKey.Tag != 0 {
		return nil, nil, fmt.Errorf("KGA EncryptedKey does not use envelopedData")
	}
	envelopeDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: encryptedKey.Bytes})
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), certChoice.Bytes...), envelopeDER, nil
}

// matchKGAKeyAndCertificate confirms the delivered private key corresponds to
// the issued certificate's public key.
func matchKGAKeyAndCertificate(key crypto.Signer, cert *x509.Certificate) error {
	keyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	certDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(keyDER, certDER) {
		return fmt.Errorf("KGA private key does not match the issued certificate")
	}
	return nil
}
