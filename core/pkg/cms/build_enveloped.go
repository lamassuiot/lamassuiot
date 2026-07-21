package cms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// EnvelopedDataInput describes a CMS EnvelopedData (RFC 5652) delivering
// Content, confidentiality-protected, to RecipientCert's public key. The
// technique is derived from the recipient key type: RSA → ktri (key transport),
// ECDSA → kari (ECDH key agreement, which additionally requires OriginatorKey
// and OriginatorCert).
type EnvelopedDataInput struct {
	// Content is the DER (or arbitrary bytes) to encrypt.
	Content []byte
	// ContentType is the EncryptedContentInfo contentType describing Content
	// (e.g. OIDSignedData() when Content is a SignedData, OIDData() for a bare
	// certificate or nonce).
	ContentType asn1.ObjectIdentifier

	// RecipientCert is the credential the CEK is protected to. Its public key
	// encrypts (KTRI) or derives (KARI) the CEK and its issuerAndSerialNumber /
	// subjectKeyIdentifier identifies the recipient in the RecipientInfo.
	RecipientCert *x509.Certificate

	// OriginatorKey is the static EC key-agreement private key used as the CMS
	// originator for KARI (its certificate is what the recipient runs ECDH
	// against). Required for KARI, ignored for KTRI.
	OriginatorKey *ecdsa.PrivateKey
	// OriginatorCert identifies the originator in the kari RecipientInfo and
	// MUST be the certificate the recipient sees as the response protection cert
	// (extraCerts[0]) so its ECDH derivation matches. Required for KARI.
	OriginatorCert *x509.Certificate

	// RecipientIDOverride, when non-nil, overrides the RecipientInfo identifier
	// with the issuerAndSerialNumber CHOICE carrying these values instead of the
	// recipient certificate's SubjectKeyIdentifier (see IssuerAndSerial).
	RecipientIDOverride *IssuerAndSerial
}

// BuildEnvelopedData produces the DER of a CMS EnvelopedData delivering
// in.Content to in.RecipientCert's public key.
func BuildEnvelopedData(in EnvelopedDataInput) ([]byte, error) {
	if in.RecipientCert == nil {
		return nil, fmt.Errorf("cms: RecipientCert is required")
	}

	technique, err := TechniqueFor(in.RecipientCert.PublicKey)
	if err != nil {
		return nil, err
	}

	// 1. Fresh CEK + AES-256-CBC encryption of the content.
	cek, err := randomBytes(contentEncryptionKeyLen)
	if err != nil {
		return nil, fmt.Errorf("cms: generate CEK: %w", err)
	}
	encContentInfo, err := encryptContent(cek, in.Content, in.ContentType)
	if err != nil {
		return nil, fmt.Errorf("cms: encrypt content: %w", err)
	}

	// 2. RecipientInfo delivering the CEK.
	var recipInfoDER []byte
	switch technique {
	case TechniqueKeyTransport:
		recipInfoDER, err = buildKTRI(in, cek)
	case TechniqueKeyAgreement:
		recipInfoDER, err = buildKARI(in, cek)
	}
	if err != nil {
		return nil, fmt.Errorf("cms: build %s recipientInfo: %w", technique, err)
	}

	// 3. EnvelopedData { recipientInfos SET OF, encryptedContentInfo }. Any ktri
	// with a subjectKeyIdentifier rid or any kari present ⇒ CMSVersion 2
	// (RFC 5652 §6.1); the RFC 9483 §4.1.6 validator also requires version 2.
	recipInfosSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      recipInfoDER,
	})
	if err != nil {
		return nil, fmt.Errorf("cms: marshal recipientInfos: %w", err)
	}

	env := envelopedData{
		Version:              2,
		RecipientInfos:       asn1.RawValue{FullBytes: recipInfosSet},
		EncryptedContentInfo: encContentInfo,
	}
	der, err := asn1.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("cms: marshal EnvelopedData: %w", err)
	}
	return der, nil
}

// encryptContent AES-256-CBC-encrypts plaintext under cek and returns the
// EncryptedContentInfo (contentType, algorithm AES-256-CBC with the IV in
// parameters, and the ciphertext in the IMPLICIT [0] field).
func encryptContent(cek, plaintext []byte, contentType asn1.ObjectIdentifier) (encryptedContentInfo, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return encryptedContentInfo{}, fmt.Errorf("new AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := randReader.Read(iv); err != nil {
		return encryptedContentInfo{}, fmt.Errorf("generate IV: %w", err)
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	ivParam, err := asn1.Marshal(iv) // AES-CBC parameters ::= OCTET STRING (the IV)
	if err != nil {
		return encryptedContentInfo{}, fmt.Errorf("marshal IV: %w", err)
	}
	return encryptedContentInfo{
		ContentType: contentType,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivParam},
		},
		EncryptedContent: ciphertext,
	}, nil
}

// pkcs7Pad appends PKCS#7 padding so the result is a whole number of blockSize
// blocks (RFC 5652 §6.3).
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// buildKTRI builds a KeyTransRecipientInfo (RFC 5652 §6.2.1) that RSA-OAEP
// encrypts the CEK to the recipient's key-transport public key. Returned DER is
// the untagged ktri alternative of the RecipientInfo CHOICE.
//
// RSAES-OAEP (RFC 9481, RFC 8017 §7.1), not the legacy PKCS#1 v1.5 encryption
// scheme, is mandatory here: PKCS#1 v1.5 encryption is vulnerable to
// Bleichenbacher/ROBOT-style padding-oracle attacks, which is precisely why
// CMP key transport specifies OAEP instead.
func buildKTRI(in EnvelopedDataInput, cek []byte) ([]byte, error) {
	rsaPub, ok := in.RecipientCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("recipient key is %T, not RSA", in.RecipientCert.PublicKey)
	}
	// label=nil selects the default empty pSourceFunc (pSpecifiedEmpty),
	// matching the omitted pSourceFunc in rsaOAEPKeyEncryptionAlgorithm below.
	encKey, err := rsa.EncryptOAEP(sha256.New(), randReader, rsaPub, cek, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encrypt CEK: %w", err)
	}
	keyEncAlg, err := rsaOAEPKeyEncryptionAlgorithm()
	if err != nil {
		return nil, fmt.Errorf("build RSAES-OAEP-params: %w", err)
	}

	// RecipientIdentifier: an explicit override always uses the
	// issuerAndSerialNumber CHOICE (version 0). Otherwise a recipient cert with
	// a subjectKeyIdentifier uses the subjectKeyIdentifier CHOICE (which forces
	// ktri version 2); issuerAndSerialNumber (version 0) is the fallback.
	var rid asn1.RawValue
	version := 0
	if in.RecipientIDOverride != nil {
		rid, err = marshalIssuerAndSerialRID(in.RecipientIDOverride)
	} else {
		rid, version, err = recipientIdentifier(in.RecipientCert)
	}
	if err != nil {
		return nil, err
	}
	ktri := keyTransRecipientInfo{
		Version:                version,
		RID:                    rid,
		KeyEncryptionAlgorithm: keyEncAlg,
		EncryptedKey:           encKey,
	}
	return asn1.Marshal(ktri)
}

// rsaOAEPKeyEncryptionAlgorithm builds the ktri KeyEncryptionAlgorithm
// AlgorithmIdentifier for RSAES-OAEP with SHA-256 as both the OAEP hash and the
// MGF1 hash (RFC 8017 §A.2.1, RFC 4055 §4.1).
func rsaOAEPKeyEncryptionAlgorithm() (pkix.AlgorithmIdentifier, error) {
	sha256AlgID, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256})
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	paramsDER, err := asn1.Marshal(rsaesOAEPParams{
		HashFunc: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		MaskGenFunc: pkix.AlgorithmIdentifier{
			Algorithm:  oidMGF1,
			Parameters: asn1.RawValue{FullBytes: sha256AlgID},
		},
	})
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	return pkix.AlgorithmIdentifier{
		Algorithm:  oidRSAESOAEP,
		Parameters: asn1.RawValue{FullBytes: paramsDER},
	}, nil
}

// marshalIssuerAndSerialRID encodes an issuerAndSerialNumber CHOICE (untagged
// SEQUENCE, RFC 5652 §6.2.1/§10.2.4) from an explicit override.
func marshalIssuerAndSerialRID(ovr *IssuerAndSerial) (asn1.RawValue, error) {
	isnDER, err := asn1.Marshal(issuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: ovr.IssuerDER},
		SerialNumber: ovr.Serial,
	})
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: isnDER}, nil
}

// recipientIdentifier builds the ktri RecipientIdentifier CHOICE for cert and
// returns it together with the KeyTransRecipientInfo version it implies:
// subjectKeyIdentifier [0] (version 2) when the cert has an SKI, else
// issuerAndSerialNumber (version 0).
func recipientIdentifier(cert *x509.Certificate) (asn1.RawValue, int, error) {
	if len(cert.SubjectKeyId) > 0 {
		// subjectKeyIdentifier [0] IMPLICIT SubjectKeyIdentifier (OCTET STRING).
		return asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: false, Bytes: cert.SubjectKeyId,
		}, 2, nil
	}
	rid, err := marshalIssuerAndSerialRID(&IssuerAndSerial{IssuerDER: cert.RawIssuer, Serial: cert.SerialNumber})
	if err != nil {
		return asn1.RawValue{}, 0, err
	}
	return rid, 0, nil
}

// buildKARI builds a KeyAgreeRecipientInfo: static ECDH between the originator
// key and the recipient's EC key-agreement public key, ANSI-X9.63 KDF (SHA-256)
// to a 256-bit KEK, then RFC 3394 AES-256 key wrap of the CEK. Returned DER is
// the IMPLICIT [1] kari alternative of the RecipientInfo CHOICE.
func buildKARI(in EnvelopedDataInput, cek []byte) ([]byte, error) {
	if in.OriginatorKey == nil || in.OriginatorCert == nil {
		return nil, fmt.Errorf("kari requires OriginatorKey and OriginatorCert")
	}
	eePub, ok := in.RecipientCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("recipient key is %T, not ECDSA", in.RecipientCert.PublicKey)
	}

	// Static ECDH → shared secret Z (the X coordinate).
	origECDH, err := in.OriginatorKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("originator key not ECDH-capable: %w", err)
	}
	eeECDH, err := eePub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("recipient key not ECDH-capable: %w", err)
	}
	z, err := origECDH.ECDH(eeECDH)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// KEK = X9.63-KDF(Z, 32, ECC-CMS-SharedInfo{ keyInfo=aes256-wrap, suppPubInfo=256 }).
	sharedInfo, err := eccCMSSharedInfo(oidAES256Wrap, 256)
	if err != nil {
		return nil, err
	}
	kek := ansiX963KDFSHA256(z, contentEncryptionKeyLen, sharedInfo)

	wrapped, err := aesKeyWrap(kek, cek)
	if err != nil {
		return nil, fmt.Errorf("AES key wrap: %w", err)
	}

	// keyEncryptionAlgorithm: dhSinglePass-stdDH-sha256kdf-scheme with the
	// KeyWrapAlgorithm (aes256-wrap) as parameters.
	kwAlg, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidAES256Wrap})
	if err != nil {
		return nil, err
	}

	// Both the originator and the recipientEncryptedKey identifier are matched
	// against the originator cert (extraCerts[0]) by subjectKeyIdentifier; the
	// end-entity cert's identity never appears in a KARI structure (only its
	// public key participates in the ECDH above).
	if len(in.OriginatorCert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("kari originator certificate has no SubjectKeyId")
	}
	ski := in.OriginatorCert.SubjectKeyId

	// originator [0] EXPLICIT OriginatorIdentifierOrKey, chosen as
	// subjectKeyIdentifier [0] IMPLICIT SubjectKeyIdentifier (OCTET STRING).
	origSKIChoice, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: false, Bytes: ski,
	})
	if err != nil {
		return nil, err
	}
	origExplicit, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: origSKIChoice,
	})
	if err != nil {
		return nil, err
	}

	// rid: with an override the KeyAgreeRecipientIdentifier CHOICE takes the
	// untagged issuerAndSerialNumber alternative; otherwise rKeyId [0] IMPLICIT
	// RecipientKeyIdentifier ::= SEQUENCE { subjectKeyIdentifier OCTET STRING,
	// ... } carrying the originator cert's SKI (the optional date/other omitted).
	var recipRID asn1.RawValue
	if in.RecipientIDOverride != nil {
		recipRID, err = marshalIssuerAndSerialRID(in.RecipientIDOverride)
		if err != nil {
			return nil, err
		}
	} else {
		skiOctet, err := asn1.Marshal(ski) // OCTET STRING
		if err != nil {
			return nil, err
		}
		rKeyID, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: skiOctet,
		})
		if err != nil {
			return nil, err
		}
		recipRID = asn1.RawValue{FullBytes: rKeyID}
	}

	kari := keyAgreeRecipientInfo{
		Version:    3,
		Originator: asn1.RawValue{FullBytes: origExplicit},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidDHSinglePassStdDHSHA256,
			Parameters: asn1.RawValue{FullBytes: kwAlg},
		},
		RecipientEncryptedKeys: []recipientEncryptedKey{{
			RID:          recipRID,
			EncryptedKey: wrapped,
		}},
	}
	seqDER, err := asn1.Marshal(kari)
	if err != nil {
		return nil, err
	}
	// Re-tag the SEQUENCE as IMPLICIT [1] (the kari alternative).
	return reTag(seqDER, asn1.ClassContextSpecific, 1)
}
