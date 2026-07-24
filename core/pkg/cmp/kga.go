package cmp

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"time"
)

var (
	kgaOIDSignedData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	kgaOIDContentType           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	kgaOIDMessageDigest         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	kgaOIDKeyPackage            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 2, 78, 5}
	kgaOIDSHA256                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	kgaOIDSHA256WithRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	kgaOIDECDSAWithSHA256       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	kgaOIDRSAESOAEP             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	kgaOIDMGF1                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	kgaOIDAES256CBC             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	kgaOIDAES256Wrap            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}
	kgaOIDDHSinglePassSHA256    = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}
	kgaOIDExtendedKeyUsageCMKGA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 32}
)

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
	signedDataDER, err := decryptKGAEnvelope(envelopeDER, options.Recipient, message.ExtraCerts)
	if err != nil {
		return result, err
	}
	result.PrivateKey, result.KGASigner, err = decodeAndVerifyKGAKeyPackage(signedDataDER, message.ExtraCerts, options)
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

type kgaEnvelopedData struct {
	Version              int
	RecipientInfos       asn1.RawValue
	EncryptedContentInfo kgaEncryptedContentInfo
}

type kgaEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"optional,tag:0"`
}

type kgaKeyTransRecipientInfo struct {
	Version                int
	RID                    asn1.RawValue
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type kgaKeyAgreeRecipientInfo struct {
	Version                int
	Originator             asn1.RawValue
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	RecipientEncryptedKeys []kgaRecipientEncryptedKey
}

type kgaRecipientEncryptedKey struct {
	RID          asn1.RawValue
	EncryptedKey []byte
}

type kgaOAEPParams struct {
	HashFunc    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MaskGenFunc pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
}

func decryptKGAEnvelope(der []byte, recipient crypto.Signer, extraCerts []*x509.Certificate) ([]byte, error) {
	var envelope kgaEnvelopedData
	if rest, err := asn1.Unmarshal(der, &envelope); err != nil {
		return nil, fmt.Errorf("decode KGA EnvelopedData: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("decode KGA EnvelopedData: %d trailing bytes", len(rest))
	}
	if envelope.RecipientInfos.Tag != asn1.TagSet {
		return nil, fmt.Errorf("KGA recipientInfos is not a SET")
	}
	var recipientInfo asn1.RawValue
	if rest, err := asn1.Unmarshal(envelope.RecipientInfos.Bytes, &recipientInfo); err != nil {
		return nil, fmt.Errorf("decode KGA RecipientInfo: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("decode KGA RecipientInfo: %d trailing bytes", len(rest))
	}
	var cek []byte
	var err error
	switch {
	case recipientInfo.Class == asn1.ClassUniversal && recipientInfo.Tag == asn1.TagSequence:
		cek, err = decryptKGAKTRI(recipientInfo.FullBytes, recipient)
	case recipientInfo.Class == asn1.ClassContextSpecific && recipientInfo.Tag == 1:
		cek, err = decryptKGAKARI(recipientInfo, recipient, extraCerts)
	default:
		err = fmt.Errorf("unsupported KGA RecipientInfo class=%d tag=%d", recipientInfo.Class, recipientInfo.Tag)
	}
	if err != nil {
		return nil, err
	}
	return decryptKGAContent(envelope.EncryptedContentInfo, cek)
}

func decryptKGAKTRI(der []byte, recipient crypto.Signer) ([]byte, error) {
	key, ok := recipient.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("KGA KTRI requires an RSA private key, got %T", recipient)
	}
	var info kgaKeyTransRecipientInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("decode KGA KTRI: %w", err)
	}
	if !info.KeyEncryptionAlgorithm.Algorithm.Equal(kgaOIDRSAESOAEP) {
		return nil, fmt.Errorf("unsupported KGA key transport algorithm %s", info.KeyEncryptionAlgorithm.Algorithm)
	}
	var params kgaOAEPParams
	if _, err := asn1.Unmarshal(info.KeyEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("decode RSAES-OAEP parameters: %w", err)
	}
	if !params.HashFunc.Algorithm.Equal(kgaOIDSHA256) || !params.MaskGenFunc.Algorithm.Equal(kgaOIDMGF1) {
		return nil, fmt.Errorf("KGA RSAES-OAEP must use SHA-256 and MGF1")
	}
	var mgfHash pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MaskGenFunc.Parameters.FullBytes, &mgfHash); err != nil || !mgfHash.Algorithm.Equal(kgaOIDSHA256) {
		return nil, fmt.Errorf("KGA RSAES-OAEP MGF1 must use SHA-256")
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, key, info.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt KGA content-encryption key: %w", err)
	}
	return cek, nil
}

func decryptKGAKARI(raw asn1.RawValue, recipient crypto.Signer, extraCerts []*x509.Certificate) ([]byte, error) {
	key, ok := recipient.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("KGA KARI requires an ECDSA private key, got %T", recipient)
	}
	sequenceDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: raw.Bytes})
	if err != nil {
		return nil, err
	}
	var info kgaKeyAgreeRecipientInfo
	if _, err := asn1.Unmarshal(sequenceDER, &info); err != nil {
		return nil, fmt.Errorf("decode KGA KARI: %w", err)
	}
	if !info.KeyEncryptionAlgorithm.Algorithm.Equal(kgaOIDDHSinglePassSHA256) {
		return nil, fmt.Errorf("unsupported KGA key agreement algorithm %s", info.KeyEncryptionAlgorithm.Algorithm)
	}
	var wrapAlgorithm pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(info.KeyEncryptionAlgorithm.Parameters.FullBytes, &wrapAlgorithm); err != nil || !wrapAlgorithm.Algorithm.Equal(kgaOIDAES256Wrap) {
		return nil, fmt.Errorf("KGA KARI must use AES-256 key wrap")
	}
	if len(info.RecipientEncryptedKeys) != 1 {
		return nil, fmt.Errorf("KGA KARI must contain exactly one encrypted key")
	}
	originatorCert, err := findKGAOriginator(info.Originator, extraCerts)
	if err != nil {
		return nil, err
	}
	originatorPublic, ok := originatorCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KGA KARI originator key is %T, not ECDSA", originatorCert.PublicKey)
	}
	privateECDH, err := key.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert KGA recipient key to ECDH: %w", err)
	}
	publicECDH, err := originatorPublic.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert KGA originator key to ECDH: %w", err)
	}
	z, err := privateECDH.ECDH(publicECDH)
	if err != nil {
		return nil, fmt.Errorf("derive KGA shared secret: %w", err)
	}
	sharedInfo, err := marshalKGAECCCMSSharedInfo(kgaOIDAES256Wrap, 256)
	if err != nil {
		return nil, err
	}
	kek := kgaX963KDF(z, 32, sharedInfo)
	return unwrapKGAAESKey(kek, info.RecipientEncryptedKeys[0].EncryptedKey)
}

func findKGAOriginator(originator asn1.RawValue, certs []*x509.Certificate) (*x509.Certificate, error) {
	var choice asn1.RawValue
	if _, err := asn1.Unmarshal(originator.Bytes, &choice); err != nil {
		return nil, fmt.Errorf("decode KGA KARI originator: %w", err)
	}
	if choice.Class != asn1.ClassContextSpecific || choice.Tag != 0 {
		return nil, fmt.Errorf("unsupported KGA KARI originator identifier")
	}
	for _, cert := range certs {
		if bytes.Equal(cert.SubjectKeyId, choice.Bytes) {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("KGA KARI originator certificate is missing from extraCerts")
}

func marshalKGAECCCMSSharedInfo(keyWrapOID asn1.ObjectIdentifier, bits int) ([]byte, error) {
	keyInfo, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: keyWrapOID})
	if err != nil {
		return nil, err
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(bits))
	octet, err := asn1.Marshal(length)
	if err != nil {
		return nil, err
	}
	suppPubInfo, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: octet})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(keyInfo, suppPubInfo...)})
}

func kgaX963KDF(z []byte, length int, info []byte) []byte {
	var output []byte
	for counter := uint32(1); len(output) < length; counter++ {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		hash := sha256.New()
		_, _ = hash.Write(z)
		_, _ = hash.Write(counterBytes)
		_, _ = hash.Write(info)
		output = append(output, hash.Sum(nil)...)
	}
	return output[:length]
}

func unwrapKGAAESKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("invalid AES-wrapped KGA key length %d", len(wrapped))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	a := append([]byte(nil), wrapped[:8]...)
	r := append([]byte(nil), wrapped[8:]...)
	buffer := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			copy(buffer[:8], a)
			for k := 0; k < 8; k++ {
				buffer[7-k] ^= byte(t >> (8 * k))
			}
			copy(buffer[8:], r[(i-1)*8:i*8])
			block.Decrypt(buffer, buffer)
			copy(a, buffer[:8])
			copy(r[(i-1)*8:i*8], buffer[8:])
		}
	}
	if !bytes.Equal(a, []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}) {
		return nil, fmt.Errorf("KGA AES key-wrap integrity check failed")
	}
	return r, nil
}

func decryptKGAContent(info kgaEncryptedContentInfo, cek []byte) ([]byte, error) {
	if !info.ContentType.Equal(kgaOIDSignedData) {
		return nil, fmt.Errorf("KGA encrypted content type is %s, want signedData", info.ContentType)
	}
	if !info.ContentEncryptionAlgorithm.Algorithm.Equal(kgaOIDAES256CBC) {
		return nil, fmt.Errorf("unsupported KGA content encryption algorithm %s", info.ContentEncryptionAlgorithm.Algorithm)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(info.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("decode KGA AES-CBC IV: %w", err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(info.EncryptedContent) == 0 || len(info.EncryptedContent)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid KGA AES-CBC parameters")
	}
	plaintext := make([]byte, len(info.EncryptedContent))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, info.EncryptedContent)
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > block.BlockSize() || padding > len(plaintext) {
		return nil, fmt.Errorf("invalid KGA PKCS#7 padding")
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return nil, fmt.Errorf("invalid KGA PKCS#7 padding")
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

type kgaSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo kgaEncapsulatedContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	SignerInfos      []kgaSignerInfo `asn1:"set"`
}

type kgaEncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type kgaSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type kgaAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

func decodeAndVerifyKGAKeyPackage(der []byte, extraCerts []*x509.Certificate, options KGADecryptOptions) (crypto.Signer, *x509.Certificate, error) {
	var signedData kgaSignedData
	if rest, err := asn1.Unmarshal(der, &signedData); err != nil {
		return nil, nil, fmt.Errorf("decode KGA SignedData: %w", err)
	} else if len(rest) != 0 {
		return nil, nil, fmt.Errorf("decode KGA SignedData: %d trailing bytes", len(rest))
	}
	if !signedData.EncapContentInfo.EContentType.Equal(kgaOIDKeyPackage) {
		return nil, nil, fmt.Errorf("KGA SignedData contains unexpected content type %s", signedData.EncapContentInfo.EContentType)
	}
	if len(signedData.SignerInfos) != 1 {
		return nil, nil, fmt.Errorf("KGA SignedData must contain exactly one SignerInfo")
	}
	certs, err := parseKGACertificates(signedData.Certificates)
	if err != nil {
		return nil, nil, err
	}
	certs = append(certs, extraCerts...)
	signerInfo := signedData.SignerInfos[0]
	signerCert := findKGASignerCertificate(signerInfo.SID, certs)
	if signerCert == nil {
		return nil, nil, fmt.Errorf("KGA signer certificate is missing")
	}
	if err := validateKGACertificate(signerCert, certs, options); err != nil {
		return nil, nil, err
	}
	if err := validateKGASignedAttributes(signerInfo.SignedAttrs, signedData.EncapContentInfo.EContent); err != nil {
		return nil, nil, err
	}
	// RFC 5652 §5.4: the signature covers the DER of signedAttrs RE-TAGGED as a
	// UNIVERSAL SET OF, not the IMPLICIT [0] wire encoding and not
	// encapContentInfo.
	signedAttrsForSigning, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: signerInfo.SignedAttrs.Bytes,
	})
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(signedAttrsForSigning)
	if err := verifyKGASignature(signerCert, signerInfo, digest[:]); err != nil {
		return nil, nil, err
	}
	key, err := parseKGAAsymmetricKeyPackage(signedData.EncapContentInfo.EContent)
	if err != nil {
		return nil, nil, err
	}
	return key, signerCert, nil
}

func parseKGACertificates(raw asn1.RawValue) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := raw.Bytes
	for len(rest) > 0 {
		var certRaw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &certRaw)
		if err != nil {
			return nil, fmt.Errorf("decode KGA certificate set: %w", err)
		}
		cert, err := x509.ParseCertificate(certRaw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("parse KGA certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func findKGASignerCertificate(sid asn1.RawValue, certs []*x509.Certificate) *x509.Certificate {
	if sid.Class != asn1.ClassContextSpecific || sid.Tag != 0 {
		return nil
	}
	for _, cert := range certs {
		if bytes.Equal(cert.SubjectKeyId, sid.Bytes) {
			return cert
		}
	}
	return nil
}

func validateKGACertificate(signer *x509.Certificate, certs []*x509.Certificate, options KGADecryptOptions) error {
	if !containsOID(signer.UnknownExtKeyUsage, kgaOIDExtendedKeyUsageCMKGA) {
		return fmt.Errorf("KGA signer certificate lacks id-kp-cmKGA extended key usage")
	}
	if options.Roots == nil {
		return nil
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		if !bytes.Equal(cert.Raw, signer.Raw) {
			intermediates.AddCert(cert)
		}
	}
	verifyOptions := x509.VerifyOptions{Roots: options.Roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: options.CurrentTime}
	if _, err := signer.Verify(verifyOptions); err != nil {
		return fmt.Errorf("verify KGA signer certificate: %w", err)
	}
	return nil
}

func containsOID(oids []asn1.ObjectIdentifier, target asn1.ObjectIdentifier) bool {
	for _, oid := range oids {
		if oid.Equal(target) {
			return true
		}
	}
	return false
}

func validateKGASignedAttributes(raw asn1.RawValue, content []byte) error {
	digest := sha256.Sum256(content)
	foundType, foundDigest := false, false
	rest := raw.Bytes
	for len(rest) > 0 {
		var attribute kgaAttribute
		var err error
		rest, err = asn1.Unmarshal(rest, &attribute)
		if err != nil {
			return fmt.Errorf("decode KGA signed attribute: %w", err)
		}
		switch {
		case attribute.Type.Equal(kgaOIDContentType):
			var contentType asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(attribute.Values.Bytes, &contentType); err != nil || !contentType.Equal(kgaOIDKeyPackage) {
				return fmt.Errorf("invalid KGA contentType signed attribute")
			}
			foundType = true
		case attribute.Type.Equal(kgaOIDMessageDigest):
			var value []byte
			if _, err := asn1.Unmarshal(attribute.Values.Bytes, &value); err != nil || !bytes.Equal(value, digest[:]) {
				return fmt.Errorf("invalid KGA messageDigest signed attribute")
			}
			foundDigest = true
		}
	}
	if !foundType || !foundDigest {
		return fmt.Errorf("KGA SignedData lacks mandatory signed attributes")
	}
	return nil
}

func verifyKGASignature(cert *x509.Certificate, info kgaSignerInfo, digest []byte) error {
	if !info.DigestAlgorithm.Algorithm.Equal(kgaOIDSHA256) {
		return fmt.Errorf("unsupported KGA digest algorithm %s", info.DigestAlgorithm.Algorithm)
	}
	switch publicKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if !info.SignatureAlgorithm.Algorithm.Equal(kgaOIDSHA256WithRSA) {
			return fmt.Errorf("KGA signature algorithm does not match RSA signer")
		}
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, info.Signature); err != nil {
			return fmt.Errorf("verify KGA RSA signature: %w", err)
		}
	case *ecdsa.PublicKey:
		if !info.SignatureAlgorithm.Algorithm.Equal(kgaOIDECDSAWithSHA256) || !ecdsa.VerifyASN1(publicKey, digest, info.Signature) {
			return fmt.Errorf("verify KGA ECDSA signature: invalid signature")
		}
	default:
		return fmt.Errorf("unsupported KGA signer public key type %T", publicKey)
	}
	return nil
}

func parseKGAAsymmetricKeyPackage(der []byte) (crypto.Signer, error) {
	var keyPackage asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &keyPackage); err != nil {
		return nil, fmt.Errorf("decode KGA AsymmetricKeyPackage: %w", err)
	} else if len(rest) != 0 || keyPackage.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("decode KGA AsymmetricKeyPackage: invalid sequence")
	}
	var oneKey asn1.RawValue
	if rest, err := asn1.Unmarshal(keyPackage.Bytes, &oneKey); err != nil {
		return nil, fmt.Errorf("decode KGA OneAsymmetricKey: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("decode KGA OneAsymmetricKey: %d trailing bytes", len(rest))
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(oneKey.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("parse KGA private key: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("KGA private key type %T is not a crypto.Signer", privateKey)
	}
	return signer, nil
}

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
