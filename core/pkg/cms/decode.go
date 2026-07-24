package cms

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
	"fmt"
	"time"
)

// DecryptEnvelopedData decrypts a CMS EnvelopedData (RFC 5652) with the
// recipient's private key, returning the plaintext content and its content
// type. It supports ktri (RSA-OAEP key transport) and kari (ECDH key
// agreement); for kari the originator certificate is located in extraCerts by
// its subjectKeyIdentifier.
func DecryptEnvelopedData(der []byte, recipient crypto.Signer, extraCerts []*x509.Certificate) (content []byte, contentType asn1.ObjectIdentifier, err error) {
	var envelope envelopedData
	if rest, err := asn1.Unmarshal(der, &envelope); err != nil {
		return nil, nil, fmt.Errorf("decode EnvelopedData: %w", err)
	} else if len(rest) != 0 {
		return nil, nil, fmt.Errorf("decode EnvelopedData: %d trailing bytes", len(rest))
	}
	if envelope.RecipientInfos.Tag != asn1.TagSet {
		return nil, nil, fmt.Errorf("recipientInfos is not a SET")
	}
	var recipientInfo asn1.RawValue
	if rest, err := asn1.Unmarshal(envelope.RecipientInfos.Bytes, &recipientInfo); err != nil {
		return nil, nil, fmt.Errorf("decode RecipientInfo: %w", err)
	} else if len(rest) != 0 {
		return nil, nil, fmt.Errorf("decode RecipientInfo: %d trailing bytes", len(rest))
	}
	var cek []byte
	switch {
	case recipientInfo.Class == asn1.ClassUniversal && recipientInfo.Tag == asn1.TagSequence:
		cek, err = decryptKTRI(recipientInfo.FullBytes, recipient)
	case recipientInfo.Class == asn1.ClassContextSpecific && recipientInfo.Tag == 1:
		cek, err = decryptKARI(recipientInfo, recipient, extraCerts)
	default:
		err = fmt.Errorf("unsupported RecipientInfo class=%d tag=%d", recipientInfo.Class, recipientInfo.Tag)
	}
	if err != nil {
		return nil, nil, err
	}
	content, err = decryptContent(envelope.EncryptedContentInfo, cek)
	if err != nil {
		return nil, nil, err
	}
	return content, envelope.EncryptedContentInfo.ContentType, nil
}

func decryptKTRI(der []byte, recipient crypto.Signer) ([]byte, error) {
	key, ok := recipient.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ktri requires an RSA private key, got %T", recipient)
	}
	var info keyTransRecipientInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("decode ktri: %w", err)
	}
	if !info.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAESOAEP) {
		return nil, fmt.Errorf("unsupported key transport algorithm %s", info.KeyEncryptionAlgorithm.Algorithm)
	}
	var params rsaesOAEPParams
	if _, err := asn1.Unmarshal(info.KeyEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("decode RSAES-OAEP parameters: %w", err)
	}
	if !params.HashFunc.Algorithm.Equal(oidSHA256) || !params.MaskGenFunc.Algorithm.Equal(oidMGF1) {
		return nil, fmt.Errorf("RSAES-OAEP must use SHA-256 and MGF1")
	}
	var mgfHash pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MaskGenFunc.Parameters.FullBytes, &mgfHash); err != nil || !mgfHash.Algorithm.Equal(oidSHA256) {
		return nil, fmt.Errorf("RSAES-OAEP MGF1 must use SHA-256")
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, key, info.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt content-encryption key: %w", err)
	}
	return cek, nil
}

func decryptKARI(raw asn1.RawValue, recipient crypto.Signer, extraCerts []*x509.Certificate) ([]byte, error) {
	key, ok := recipient.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("kari requires an ECDSA private key, got %T", recipient)
	}
	sequenceDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: raw.Bytes})
	if err != nil {
		return nil, err
	}
	var info keyAgreeRecipientInfo
	if _, err := asn1.Unmarshal(sequenceDER, &info); err != nil {
		return nil, fmt.Errorf("decode kari: %w", err)
	}
	if !info.KeyEncryptionAlgorithm.Algorithm.Equal(oidDHSinglePassStdDHSHA256) {
		return nil, fmt.Errorf("unsupported key agreement algorithm %s", info.KeyEncryptionAlgorithm.Algorithm)
	}
	var wrapAlgorithm pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(info.KeyEncryptionAlgorithm.Parameters.FullBytes, &wrapAlgorithm); err != nil || !wrapAlgorithm.Algorithm.Equal(oidAES256Wrap) {
		return nil, fmt.Errorf("kari must use AES-256 key wrap")
	}
	if len(info.RecipientEncryptedKeys) != 1 {
		return nil, fmt.Errorf("kari must contain exactly one encrypted key")
	}
	originatorCert, err := findOriginator(info.Originator, extraCerts)
	if err != nil {
		return nil, err
	}
	originatorPublic, ok := originatorCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("kari originator key is %T, not ECDSA", originatorCert.PublicKey)
	}
	privateECDH, err := key.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert recipient key to ECDH: %w", err)
	}
	publicECDH, err := originatorPublic.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert originator key to ECDH: %w", err)
	}
	z, err := privateECDH.ECDH(publicECDH)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}
	sharedInfo, err := eccCMSSharedInfo(oidAES256Wrap, 256)
	if err != nil {
		return nil, err
	}
	kek := ansiX963KDFSHA256(z, contentEncryptionKeyLen, sharedInfo)
	return aesKeyUnwrap(kek, info.RecipientEncryptedKeys[0].EncryptedKey)
}

func findOriginator(originator asn1.RawValue, certs []*x509.Certificate) (*x509.Certificate, error) {
	var choice asn1.RawValue
	if _, err := asn1.Unmarshal(originator.Bytes, &choice); err != nil {
		return nil, fmt.Errorf("decode kari originator: %w", err)
	}
	if choice.Class != asn1.ClassContextSpecific || choice.Tag != 0 {
		return nil, fmt.Errorf("unsupported kari originator identifier")
	}
	for _, cert := range certs {
		if bytes.Equal(cert.SubjectKeyId, choice.Bytes) {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("kari originator certificate is missing from extraCerts")
}

func decryptContent(info encryptedContentInfo, cek []byte) ([]byte, error) {
	if !info.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256CBC) {
		return nil, fmt.Errorf("unsupported content encryption algorithm %s", info.ContentEncryptionAlgorithm.Algorithm)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(info.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("decode AES-CBC IV: %w", err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(info.EncryptedContent) == 0 || len(info.EncryptedContent)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid AES-CBC parameters")
	}
	plaintext := make([]byte, len(info.EncryptedContent))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, info.EncryptedContent)
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > block.BlockSize() || padding > len(plaintext) {
		return nil, fmt.Errorf("invalid PKCS#7 padding")
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return nil, fmt.Errorf("invalid PKCS#7 padding")
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

// VerifyOptions controls VerifySignedData.
type VerifyOptions struct {
	// Roots, when non-nil, is the trust anchor set the signer certificate is
	// chain-validated against. When nil, the CMS signature is still verified but
	// the signer certificate chain is not (useful for tests).
	Roots *x509.CertPool
	// CurrentTime is the reference time for chain validation (zero = now).
	CurrentTime time.Time
	// RequiredEKUs are extended-key-usage OIDs the signer certificate MUST carry
	// (e.g. id-kp-cmKGA for a KGA response). May be empty.
	RequiredEKUs []asn1.ObjectIdentifier
}

// VerifiedSignedData is the successfully-verified content of a CMS SignedData.
type VerifiedSignedData struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte
	SignerCert   *x509.Certificate
}

// VerifySignedData decodes a CMS SignedData (RFC 5652), locates the single
// SignerInfo's certificate (by subjectKeyIdentifier, from the SignedData
// certificates plus extraCerts), enforces opts, validates the mandatory signed
// attributes (contentType matching the eContentType, and messageDigest over the
// eContent), and verifies the signature over the EncapsulatedContentInfo DER.
func VerifySignedData(der []byte, extraCerts []*x509.Certificate, opts VerifyOptions) (VerifiedSignedData, error) {
	var sd signedData
	if rest, err := asn1.Unmarshal(der, &sd); err != nil {
		return VerifiedSignedData{}, fmt.Errorf("decode SignedData: %w", err)
	} else if len(rest) != 0 {
		return VerifiedSignedData{}, fmt.Errorf("decode SignedData: %d trailing bytes", len(rest))
	}
	if len(sd.SignerInfos) != 1 {
		return VerifiedSignedData{}, fmt.Errorf("SignedData must contain exactly one SignerInfo")
	}
	certs, err := parseCertificates(sd.Certificates)
	if err != nil {
		return VerifiedSignedData{}, err
	}
	certs = append(certs, extraCerts...)
	si := sd.SignerInfos[0]
	signerCert := findSignerCertificate(si.SID, certs)
	if signerCert == nil {
		return VerifiedSignedData{}, fmt.Errorf("signer certificate is missing")
	}
	if err := validateSignerCertificate(signerCert, certs, opts); err != nil {
		return VerifiedSignedData{}, err
	}
	if err := validateSignedAttributes(si.SignedAttrs, sd.EncapContentInfo.EContentType, sd.EncapContentInfo.EContent); err != nil {
		return VerifiedSignedData{}, err
	}
	// RFC 5652 §5.4: the signature covers the DER of signedAttrs RE-TAGGED as a
	// UNIVERSAL SET OF — not the IMPLICIT [0] wire form, and NOT the
	// encapContentInfo. This must recompute the exact bytes BuildSignedData
	// signed (and that any conformant signer, e.g. openssl, produces).
	signedAttrsForSigning, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: si.SignedAttrs.Bytes,
	})
	if err != nil {
		return VerifiedSignedData{}, err
	}
	digest := sha256.Sum256(signedAttrsForSigning)
	if err := verifySignature(signerCert, si, digest[:]); err != nil {
		return VerifiedSignedData{}, err
	}
	return VerifiedSignedData{
		EContentType: sd.EncapContentInfo.EContentType,
		EContent:     sd.EncapContentInfo.EContent,
		SignerCert:   signerCert,
	}, nil
}

func parseCertificates(raw asn1.RawValue) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := raw.Bytes
	for len(rest) > 0 {
		var certRaw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &certRaw)
		if err != nil {
			return nil, fmt.Errorf("decode certificate set: %w", err)
		}
		cert, err := x509.ParseCertificate(certRaw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func findSignerCertificate(sid asn1.RawValue, certs []*x509.Certificate) *x509.Certificate {
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

func validateSignerCertificate(signer *x509.Certificate, certs []*x509.Certificate, opts VerifyOptions) error {
	for _, eku := range opts.RequiredEKUs {
		if !containsOID(signer.UnknownExtKeyUsage, eku) {
			return fmt.Errorf("signer certificate lacks required extended key usage %s", eku)
		}
	}
	if opts.Roots == nil {
		return nil
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		if !bytes.Equal(cert.Raw, signer.Raw) {
			intermediates.AddCert(cert)
		}
	}
	verifyOptions := x509.VerifyOptions{Roots: opts.Roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: opts.CurrentTime}
	if _, err := signer.Verify(verifyOptions); err != nil {
		return fmt.Errorf("verify signer certificate: %w", err)
	}
	return nil
}

func validateSignedAttributes(raw asn1.RawValue, eContentType asn1.ObjectIdentifier, content []byte) error {
	digest := sha256.Sum256(content)
	foundType, foundDigest := false, false
	rest := raw.Bytes
	for len(rest) > 0 {
		var attr attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return fmt.Errorf("decode signed attribute: %w", err)
		}
		switch {
		case attr.Type.Equal(oidContentType):
			var contentType asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &contentType); err != nil || !contentType.Equal(eContentType) {
				return fmt.Errorf("invalid contentType signed attribute")
			}
			foundType = true
		case attr.Type.Equal(oidMessageDigest):
			var value []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &value); err != nil || !bytes.Equal(value, digest[:]) {
				return fmt.Errorf("invalid messageDigest signed attribute")
			}
			foundDigest = true
		}
	}
	if !foundType || !foundDigest {
		return fmt.Errorf("SignedData lacks mandatory signed attributes")
	}
	return nil
}

func verifySignature(cert *x509.Certificate, info signerInfo, digest []byte) error {
	if !info.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		return fmt.Errorf("unsupported digest algorithm %s", info.DigestAlgorithm.Algorithm)
	}
	switch publicKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if !info.SignatureAlgorithm.Algorithm.Equal(oidSHA256WithRSA) {
			return fmt.Errorf("signature algorithm does not match RSA signer")
		}
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, info.Signature); err != nil {
			return fmt.Errorf("verify RSA signature: %w", err)
		}
	case *ecdsa.PublicKey:
		if !info.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA256) || !ecdsa.VerifyASN1(publicKey, digest, info.Signature) {
			return fmt.Errorf("verify ECDSA signature: invalid signature")
		}
	default:
		return fmt.Errorf("unsupported signer public key type %T", publicKey)
	}
	return nil
}
