package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// SignedDataInput describes a CMS SignedData (RFC 5652) to be produced with a
// single signer identified by its subjectKeyIdentifier.
type SignedDataInput struct {
	// EContentType is the eContentType of the encapsulated content (e.g.
	// OIDKeyPackage() for an AsymmetricKeyPackage).
	EContentType asn1.ObjectIdentifier
	// EContent is the DER of the content to encapsulate and sign.
	EContent []byte
	// SignerCert is the signing certificate. It is embedded in
	// SignedData.certificates and its SubjectKeyId identifies the SignerInfo, so
	// it MUST carry a SubjectKeyId.
	SignerCert *x509.Certificate
	// Chain are the intermediate/root certificates completing SignerCert's chain;
	// they are included in SignedData.certificates so the recipient can validate
	// the signer up to a trust anchor. May be empty.
	Chain []*x509.Certificate
	// Signer is SignerCert's private key, used to sign the SignedData.
	Signer crypto.Signer
}

// BuildSignedData produces the DER of a CMS SignedData wrapping in.EContent,
// signed by in.Signer.
//
// It follows the RFC 9483 §4.1.6 profile: SignerInfo version 3 with a
// subjectKeyIdentifier sid; signedAttrs carrying id-contentType (= EContentType)
// and id-messageDigest (= SHA-256 over the eContent); and a signature computed
// over the DER of the EncapsulatedContentInfo.
func BuildSignedData(in SignedDataInput) ([]byte, error) {
	if len(in.EContent) == 0 {
		return nil, fmt.Errorf("cms: SignedData EContent is required")
	}
	if in.SignerCert == nil || in.Signer == nil {
		return nil, fmt.Errorf("cms: SignerCert and Signer are required")
	}
	if len(in.SignerCert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("cms: signer certificate has no SubjectKeyId")
	}

	encap := encapsulatedContentInfo{
		EContentType: in.EContentType,
		EContent:     in.EContent,
	}

	// signedAttrs: id-contentType (= EContentType) and id-messageDigest
	// (= SHA-256 over the eContent).
	msgDigest := sha256.Sum256(in.EContent)
	attrValues, err := marshalSignedAttrValues(in.EContentType, msgDigest[:])
	if err != nil {
		return nil, err
	}
	// Wire form: IMPLICIT [0] (RFC 5652 §5.3 SignerInfo.signedAttrs).
	signedAttrsImplicit, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrValues,
	})
	if err != nil {
		return nil, fmt.Errorf("cms: marshal signedAttrs (implicit): %w", err)
	}
	// Signing form: RFC 5652 §5.4 requires the signature to cover the DER of
	// signedAttrs RE-TAGGED as a UNIVERSAL SET OF — NOT the IMPLICIT [0] wire
	// form, and NOT the encapContentInfo. An earlier revision signed over
	// encapContentInfo, which any conformant verifier (openssl included)
	// rejects, since it independently recomputes the digest over these bytes.
	signedAttrsForSigning, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attrValues,
	})
	if err != nil {
		return nil, fmt.Errorf("cms: marshal signedAttrs (set, for signing): %w", err)
	}

	sigAlg, err := signatureAlgorithmFor(in.Signer)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(signedAttrsForSigning)
	signature, err := in.Signer.Sign(randReader, h[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cms: sign: %w", err)
	}

	// sid = [0] subjectKeyIdentifier of the signer cert (RFC 5652 SignerIdentifier).
	sid, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   0,
		Bytes: in.SignerCert.SubjectKeyId,
	})
	if err != nil {
		return nil, fmt.Errorf("cms: marshal signer identifier: %w", err)
	}

	si := signerInfo{
		Version:            3, // subjectKeyIdentifier sid ⇒ CMS v3
		SID:                asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsImplicit},
		SignatureAlgorithm: sigAlg,
		Signature:          signature,
	}

	certsField, err := buildCertificatesField(in.SignerCert, in.Chain)
	if err != nil {
		return nil, err
	}

	sd := signedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: encap,
		Certificates:     asn1.RawValue{FullBytes: certsField},
		SignerInfos:      []signerInfo{si},
	}
	return asn1.Marshal(sd)
}

// signatureAlgorithmFor returns the CMS signature AlgorithmIdentifier matching
// the signer's key type (SHA-256 based, as used for the digest).
func signatureAlgorithmFor(signer crypto.Signer) (pkix.AlgorithmIdentifier, error) {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		// RSA carries an explicit NULL parameter (RFC 4055 / RFC 3370).
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue}, nil
	case *ecdsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}, nil
	default:
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("cms: unsupported signer key type %T", signer.Public())
	}
}

// marshalSignedAttrValues encodes the concatenated Attribute values
// (id-contentType and id-messageDigest) that make up a SignerInfo's signedAttrs
// — WITHOUT the outer SET-OF/[0] tag — so callers can apply either the wire tag
// (IMPLICIT [0], RFC 5652 §5.3) or the signing tag (UNIVERSAL SET OF,
// RFC 5652 §5.4) over the identical inner bytes.
func marshalSignedAttrValues(eContentType asn1.ObjectIdentifier, messageDigest []byte) ([]byte, error) {
	// contentType attribute: values = SET { eContentType }.
	ctOID, err := asn1.Marshal(eContentType)
	if err != nil {
		return nil, err
	}
	ctValues, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: ctOID})
	if err != nil {
		return nil, err
	}
	ctAttr, err := asn1.Marshal(attribute{Type: oidContentType, Values: asn1.RawValue{FullBytes: ctValues}})
	if err != nil {
		return nil, err
	}

	// messageDigest attribute: values = SET { OCTET STRING(digest) }.
	mdOctet, err := asn1.Marshal(messageDigest) // []byte → OCTET STRING
	if err != nil {
		return nil, err
	}
	mdValues, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: mdOctet})
	if err != nil {
		return nil, err
	}
	mdAttr, err := asn1.Marshal(attribute{Type: oidMessageDigest, Values: asn1.RawValue{FullBytes: mdValues}})
	if err != nil {
		return nil, err
	}

	// Raw concatenated attribute values (no outer tag); the caller wraps these
	// as IMPLICIT [0] for the wire and UNIVERSAL SET OF for the signature.
	return append(append([]byte{}, ctAttr...), mdAttr...), nil
}

// buildCertificatesField builds the SignedData certificates field: an IMPLICIT
// [0] CertificateSet (SET OF CertificateChoices) holding the signer cert and chain.
func buildCertificatesField(signer *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	var content []byte
	content = append(content, signer.Raw...)
	for _, c := range chain {
		if c != nil {
			content = append(content, c.Raw...)
		}
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      content,
	})
}
