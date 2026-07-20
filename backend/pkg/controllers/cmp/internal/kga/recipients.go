package kga

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
)

// buildKTRI builds a KeyTransRecipientInfo (RFC 5652 §6.2.1) that RSA-OAEP
// encrypts the CEK to the recipient's key-transport public key. Returned DER
// is the untagged ktri alternative of the RecipientInfo CHOICE.
//
// RSAES-OAEP (RFC 9481, RFC 8017 §7.1), not the legacy PKCS#1 v1.5 encryption
// scheme, is mandatory here: PKCS#1 v1.5 encryption is vulnerable to
// Bleichenbacher/ROBOT-style padding-oracle attacks, which is precisely why
// CMP key transport specifies OAEP instead.
func buildKTRI(in BuildInput, cek []byte) ([]byte, error) {
	recipientCert := in.RecipientCert
	rsaPub, ok := recipientCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("recipient key is %T, not RSA", recipientCert.PublicKey)
	}
	// label=nil selects the default empty pSourceFunc (pSpecifiedEmpty),
	// matching the omitted pSourceFunc in rsaOAEPKeyEncryptionAlgorithm below.
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, cek, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encrypt CEK: %w", err)
	}
	keyEncAlg, err := rsaOAEPKeyEncryptionAlgorithm()
	if err != nil {
		return nil, fmt.Errorf("build RSAES-OAEP-params: %w", err)
	}

	// RecipientIdentifier: an explicit RecipientRID override (CMP
	// challenge-response, RFC 9810 §5.2.8.3.3) always uses the
	// issuerAndSerialNumber CHOICE (version 0). Otherwise the RFC 9483 §4.1.6
	// validator matches rid against the recipient credential and, when that
	// cert carries a subjectKeyIdentifier (Lamassu-issued certs always do),
	// REQUIRES the subjectKeyIdentifier CHOICE (which in turn forces ktri
	// version 2); issuerAndSerialNumber (version 0) is the fallback for a
	// recipient cert without an SKI.
	var rid asn1.RawValue
	version := 0
	if in.RecipientRID != nil {
		rid, err = marshalIssuerAndSerialRID(in.RecipientRID)
	} else {
		rid, version, err = recipientIdentifier(recipientCert)
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
// AlgorithmIdentifier for RSAES-OAEP with SHA-256 as both the OAEP hash and
// the MGF1 hash (RFC 8017 §A.2.1, RFC 4055 §4.1): id-RSAES-OAEP with explicit
// hashFunc/maskGenFunc parameters (they differ from the SHA-1 defaults) and
// an absent pSourceFunc (defaults to the empty label, matching the nil label
// passed to rsa.EncryptOAEP in buildKTRI).
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
	return marshalIssuerAndSerialRIDFromCert(cert)
}

// marshalIssuerAndSerialRIDFromCert is recipientIdentifier's
// issuerAndSerialNumber fallback, split out for reuse.
func marshalIssuerAndSerialRIDFromCert(cert *x509.Certificate) (asn1.RawValue, int, error) {
	rid, err := marshalIssuerAndSerialRID(&IssuerAndSerial{IssuerDER: cert.RawIssuer, Serial: cert.SerialNumber})
	if err != nil {
		return asn1.RawValue{}, 0, err
	}
	return rid, 0, nil
}

// keyAgreeRecipientInfo is the kari CHOICE member (RFC 5652 §6.2.2). It is
// marshalled as a plain SEQUENCE and then re-tagged IMPLICIT [1] by buildKARI.
type keyAgreeRecipientInfo struct {
	Version int
	// Originator is the [0] EXPLICIT OriginatorIdentifierOrKey, pre-wrapped
	// verbatim (a RawValue with FullBytes bypasses struct-tag tagging, so the
	// [0] EXPLICIT wrapper is applied by hand in buildKARI).
	Originator             asn1.RawValue
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	RecipientEncryptedKeys []recipientEncryptedKey
}

type recipientEncryptedKey struct {
	// RID is the KeyAgreeRecipientIdentifier CHOICE, pre-marshalled as rKeyId [0]
	// (RecipientKeyIdentifier) carrying the originator cert's SKI — the RFC 9483
	// §4.1.6 validator matches it against extraCerts[0] (the originator), not the
	// end-entity cert. See buildKARI.
	RID          asn1.RawValue
	EncryptedKey []byte
}

// buildKARI builds a KeyAgreeRecipientInfo: static ECDH between the KGA/RA
// originator key and the recipient's EC key-agreement public key, ANSI-X9.63
// KDF (SHA-256) to a 256-bit KEK, then RFC 3394 AES-256 key wrap of the CEK.
// Returned DER is the IMPLICIT [1] kari alternative of the RecipientInfo CHOICE.
func buildKARI(in BuildInput, cek []byte) ([]byte, error) {
	if in.KARIOriginatorKey == nil || in.KARIOriginatorCert == nil {
		return nil, fmt.Errorf("KARI requires KARIOriginatorKey and KARIOriginatorCert")
	}
	eePub, ok := in.RecipientCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("recipient key is %T, not ECDSA", in.RecipientCert.PublicKey)
	}

	// Static ECDH → shared secret Z (the X coordinate).
	origECDH, err := in.KARIOriginatorKey.ECDH()
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

	// Both the originator and the recipientEncryptedKey identifier are matched by
	// the RFC 9483 §4.1.6 validator against extraCerts[0] — the originator cert —
	// by subjectKeyIdentifier. The end-entity cert's identity never appears in a
	// KARI structure (only its public key participates in the ECDH above).
	if len(in.KARIOriginatorCert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("KARI originator certificate has no SubjectKeyId")
	}
	ski := in.KARIOriginatorCert.SubjectKeyId

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

	// rid: with a RecipientRID override (CMP challenge-response, RFC 9810
	// §5.2.8.3.3) the KeyAgreeRecipientIdentifier CHOICE takes the untagged
	// issuerAndSerialNumber alternative; otherwise rKeyId [0] IMPLICIT
	// RecipientKeyIdentifier ::= SEQUENCE { subjectKeyIdentifier OCTET STRING,
	// ... } carrying the originator cert's SKI (the optional date/other omitted).
	var recipRID asn1.RawValue
	if in.RecipientRID != nil {
		recipRID, err = marshalIssuerAndSerialRID(in.RecipientRID)
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

// eccCMSSharedInfo builds the DER of ECC-CMS-SharedInfo (RFC 5753 §7.2):
// SEQUENCE { keyInfo AlgorithmIdentifier(keyWrapOID, no params),
// suppPubInfo [2] EXPLICIT OCTET STRING(keydatalen-in-bits, 4 bytes BE) }.
// entityUInfo is omitted (no UKM).
func eccCMSSharedInfo(keyWrapOID asn1.ObjectIdentifier, keyDataLenBits int) ([]byte, error) {
	keyInfo, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: keyWrapOID})
	if err != nil {
		return nil, err
	}
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(keyDataLenBits))
	octet, err := asn1.Marshal(lenBytes) // OCTET STRING
	if err != nil {
		return nil, err
	}
	suppPubInfo, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: octet,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte{}, keyInfo...), suppPubInfo...),
	})
}

// ansiX963KDFSHA256 is the ANSI-X9.63 KDF (SHA-256): K = H(Z || counter || info)
// concatenated until keyLen bytes (RFC 5753). counter is a 4-byte big-endian
// value starting at 1.
func ansiX963KDFSHA256(z []byte, keyLen int, info []byte) []byte {
	var out []byte
	counter := uint32(1)
	for len(out) < keyLen {
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		h := sha256.New()
		h.Write(z)
		h.Write(ctr[:])
		h.Write(info)
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:keyLen]
}

// reTag rewrites the outer tag of a single DER TLV to (class, tag), preserving
// its content and constructed bit. Used to turn a marshalled SEQUENCE into an
// IMPLICIT context-tagged value.
func reTag(der []byte, class, tag int) ([]byte, error) {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      class,
		Tag:        tag,
		IsCompound: rv.IsCompound,
		Bytes:      rv.Bytes,
	})
}
