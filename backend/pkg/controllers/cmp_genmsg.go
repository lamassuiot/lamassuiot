package controllers

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// CMP General Message / General Response support (RFC 9483 §4.3, RFC 4210
// §5.3.19/§5.3.20). The EE sends a genm (PKIBody [21]) carrying a SEQUENCE OF
// InfoTypeAndValue and the CA replies with a genp (PKIBody [22]) carrying the
// requested information keyed by the same id-it-* OIDs.
//
// id-it OID arc is 1.3.6.1.5.5.7.4.* (RFC 4210 Appendix F / RFC 9480).
var (
	oidItCaProtEncCert    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 1}  // §4.3 / RFC4210 5.3.19.1
	oidItSignKeyPairTypes = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 2}  // 5.3.19.2
	oidItEncKeyPairTypes  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 3}  // 5.3.19.3
	oidItPreferredSymmAlg = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 4}  // 5.3.19.4
	oidItCurrentCRL       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 6}  // 5.3.19.6
	oidItSuppLangTags     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 16} // 5.3.19.13
	oidItCaCerts          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 17} // RFC 9483 §4.3.1
	oidItRootCaKeyUpdate  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 18} // RFC 9483 §4.3.2 (genp)
	oidItCertReqTemplate  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 19} // RFC 9483 §4.3.3
	oidItRootCaCert       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 20} // RFC 9483 §4.3.2 (genm)
	oidItCrlStatusList    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 22} // RFC 9483 §4.3.4 (genm)
	oidItCrls             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 23} // RFC 9483 §4.3.4 (genp)
)

// Algorithm OIDs advertised in signing/encryption key-pair-type and preferred
// symmetric-algorithm responses.
var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// genITAV is the decoded request InfoTypeAndValue. infoValue is OPTIONAL; an
// absent value leaves InfoValue at its zero RawValue (FullBytes == nil).
type genITAV struct {
	InfoType  asn1.ObjectIdentifier
	InfoValue asn1.RawValue `asn1:"optional"`
}

// handleGeneralMessage processes a genm (21) body and answers with a genp (22).
// Signature protection has already been verified by HandleCMP; sender/senderKID
// binding is intentionally not enforced for genm (see the dispatch in cmp.go).
func (r *cmpHttpRoutes) handleGeneralMessage(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string) {
	itavs, err := decodeGenMsgContent(body.Bytes)
	if err != nil {
		lFunc.Errorf("genm: decode GenMsgContent: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed GenMsgContent", dmsID, pkiFailureInfoBadDataFormat)
		return
	}
	if len(itavs) == 0 {
		r.rejectWithError(ctx, &header, PKIStatus(2), "empty GenMsgContent", dmsID, pkiFailureInfoBadRequest)
		return
	}

	respEntries := make([][]byte, 0, len(itavs))
	for _, itav := range itavs {
		lFunc.Infof("genm: infoType=%s", itav.InfoType.String())
		entryDER, rej := r.buildGenpEntry(ctx.Request.Context(), lFunc, dmsID, itav)
		if rej != nil {
			lFunc.Warnf("genm: rejecting %s: %s", itav.InfoType.String(), rej.reason)
			r.rejectWithError(ctx, &header, PKIStatus(2), rej.reason, dmsID, rej.failInfo)
			return
		}
		respEntries = append(respEntries, entryDER)
	}

	genRepDER, err := marshalGenRepBody(respEntries)
	if err != nil {
		lFunc.Errorf("genm: build genp body: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build genp response", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	r.sendRawBody(ctx, lFunc, header, cmpBodyTagGenRep, genRepDER, dmsID)
}

// buildGenpEntry maps a single request InfoTypeAndValue to its genp response
// entry. Returns the DER of the response InfoTypeAndValue, or a rejection when
// the request violates the per-OID infoValue presence rule (RFC 9483 §4.3) or
// the underlying service call fails.
func (r *cmpHttpRoutes) buildGenpEntry(ctx context.Context, lFunc *logrus.Entry, dmsID string, itav genITAV) ([]byte, *cmpEnvelopeRejection) {
	hasValue := len(itav.InfoValue.FullBytes) > 0

	var respOID asn1.ObjectIdentifier
	var respVal []byte // nil => absent infoValue (RFC-compliant "not available")

	switch itav.InfoType.String() {

	case oidItCaCerts.String(): // §4.3.1 Get CA Certificates
		if hasValue {
			return nil, rejBadRequest("id-it-caCerts request infoValue MUST be absent")
		}
		certs, err := r.svc.LWCCACerts(ctx, dmsID)
		if err != nil {
			return nil, rejSystemFailure("cannot load CA certificates: " + err.Error())
		}
		v, err := encodeCaCertsValue(certs)
		if err != nil {
			return nil, rejSystemFailure("cannot encode caCerts")
		}
		respOID, respVal = oidItCaCerts, v

	case oidItRootCaCert.String(): // §4.3.2 Get Root CA Certificate Update
		out, err := r.svc.LWCGetRootCACertUpdate(ctx, services.GetRootCACertUpdateInput{APS: dmsID})
		if err != nil {
			return nil, rejSystemFailure("root CA update: " + err.Error())
		}
		respOID = oidItRootCaKeyUpdate
		if out != nil {
			v, encErr := encodeRootCaKeyUpdateValue(out)
			if encErr != nil {
				return nil, rejSystemFailure("cannot encode rootCaKeyUpdate")
			}
			respVal = v
		}

	case oidItCertReqTemplate.String(): // §4.3.3 Get Certificate Request Template
		if hasValue {
			return nil, rejBadRequest("id-it-certReqTemplate request infoValue MUST be absent")
		}
		out, err := r.svc.LWCGetCertReqTemplate(ctx, services.GetCertReqTemplateInput{APS: dmsID})
		if err != nil {
			return nil, rejSystemFailure("cert req template: " + err.Error())
		}
		respOID = oidItCertReqTemplate
		if out != nil {
			v, encErr := encodeCertReqTemplateValue(out)
			if encErr != nil {
				return nil, rejSystemFailure("cannot encode certReqTemplate")
			}
			respVal = v
		}

	case oidItCurrentCRL.String(): // §4.3.4 currentCRL
		if hasValue {
			return nil, rejBadRequest("id-it-currentCRL request infoValue MUST be absent")
		}
		crl, err := r.svc.LWCGetCRL(ctx, services.GetCMPCRLInput{APS: dmsID})
		if err != nil {
			return nil, rejSystemFailure("current CRL: " + err.Error())
		}
		respOID = oidItCurrentCRL
		if crl != nil {
			respVal = crl.Raw // CurrentCRLValue ::= CertificateList
		}

	case oidItCrlStatusList.String(): // §4.3.4 CRL Update Retrieval
		crl, err := r.svc.LWCGetCRL(ctx, services.GetCMPCRLInput{APS: dmsID})
		if err != nil {
			return nil, rejSystemFailure("CRL update retrieval: " + err.Error())
		}
		respOID = oidItCrls
		if crl != nil {
			v, encErr := encodeCrlsValue([]*x509.RevocationList{crl})
			if encErr != nil {
				return nil, rejSystemFailure("cannot encode crls")
			}
			respVal = v
		}

	case oidItCaProtEncCert.String(): // 5.3.19.1 CA Protocol Encryption Certificate
		if hasValue {
			return nil, rejBadRequest("id-it-caProtEncCert request infoValue MUST be absent")
		}
		// Lamassu does not provision a dedicated protocol-encryption certificate;
		// respond with the OID and an absent value (RFC 4210bis 5.3.19.1).
		respOID = oidItCaProtEncCert

	case oidItSignKeyPairTypes.String(): // 5.3.19.2 Signing Key Pair Types
		if hasValue {
			return nil, rejBadRequest("id-it-signKeyPairTypes request infoValue MUST be absent")
		}
		v, err := encodeAlgIDList(oidRSAEncryption, oidECPublicKey)
		if err != nil {
			return nil, rejSystemFailure("cannot encode signKeyPairTypes")
		}
		respOID, respVal = oidItSignKeyPairTypes, v

	case oidItEncKeyPairTypes.String(): // 5.3.19.3 Encryption/Key Agreement Key Pair Types
		if hasValue {
			return nil, rejBadRequest("id-it-encKeyPairTypes request infoValue MUST be absent")
		}
		v, err := encodeAlgIDList(oidRSAEncryption)
		if err != nil {
			return nil, rejSystemFailure("cannot encode encKeyPairTypes")
		}
		respOID, respVal = oidItEncKeyPairTypes, v

	case oidItPreferredSymmAlg.String(): // 5.3.19.4 Preferred Symmetric Algorithm
		if hasValue {
			return nil, rejBadRequest("id-it-preferredSymmAlg request infoValue MUST be absent")
		}
		v, err := encodeAlgID(oidAES256CBC)
		if err != nil {
			return nil, rejSystemFailure("cannot encode preferredSymmAlg")
		}
		respOID, respVal = oidItPreferredSymmAlg, v

	case oidItSuppLangTags.String(): // 5.3.19.13 Supported Language Tags
		// Unlike the other support messages, the request carries the EE's list
		// and the value MUST be present (RFC 4210bis 5.3.19.13).
		if !hasValue {
			return nil, rejBadRequest("id-it-supportedLangTags request requires a value")
		}
		tags, err := decodeUTF8Sequence(itav.InfoValue.FullBytes)
		if err != nil || len(tags) == 0 {
			return nil, rejBadRequest("malformed supportedLangTags value")
		}
		// The CA selects exactly one tag (the first offered) per the spec.
		v, encErr := encodeUTF8Sequence(tags[0])
		if encErr != nil {
			return nil, rejSystemFailure("cannot encode supportedLangTags")
		}
		respOID, respVal = oidItSuppLangTags, v

	default:
		return nil, &cmpEnvelopeRejection{
			reason:   "unsupported genm infoType " + itav.InfoType.String(),
			failInfo: pkiFailureInfoBadRequest,
		}
	}

	der, err := marshalInfoTypeAndValue(respOID, respVal)
	if err != nil {
		return nil, rejSystemFailure("cannot encode genp entry")
	}
	return der, nil
}

// --- rejection helpers -----------------------------------------------------

func rejBadRequest(reason string) *cmpEnvelopeRejection {
	return &cmpEnvelopeRejection{reason: reason, failInfo: pkiFailureInfoBadRequest}
}

func rejSystemFailure(reason string) *cmpEnvelopeRejection {
	return &cmpEnvelopeRejection{reason: reason, failInfo: pkiFailureInfoSystemFailure}
}

// --- decoding --------------------------------------------------------------

// decodeGenMsgContent parses the GenMsgContent SEQUENCE OF InfoTypeAndValue
// from the content bytes of the [21] PKIBody. The compliance suite encodes the
// body as [21] EXPLICIT wrapping a universal SEQUENCE, so body.Bytes begins
// with the SEQUENCE tag.
func decodeGenMsgContent(bodyBytes []byte) ([]genITAV, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &seq); err != nil {
		return nil, fmt.Errorf("GenMsgContent SEQUENCE: %w", err)
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("GenMsgContent must be a SEQUENCE, got class=%d tag=%d", seq.Class, seq.Tag)
	}
	var out []genITAV
	rest := seq.Bytes
	for len(rest) > 0 {
		var itav genITAV
		var err error
		rest, err = asn1.Unmarshal(rest, &itav)
		if err != nil {
			return nil, fmt.Errorf("InfoTypeAndValue: %w", err)
		}
		out = append(out, itav)
	}
	return out, nil
}

// decodeUTF8Sequence parses a SEQUENCE OF UTF8String value (used by the
// supportedLangTags request).
func decodeUTF8Sequence(valueDER []byte) ([]string, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(valueDER, &seq); err != nil {
		return nil, err
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("expected SEQUENCE OF UTF8String")
	}
	var out []string
	rest := seq.Bytes
	for len(rest) > 0 {
		var s string
		var err error
		rest, err = asn1.Unmarshal(rest, &s)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// --- genp content encoders -------------------------------------------------

// marshalInfoTypeAndValue produces a single InfoTypeAndValue DER. When valueDER
// is nil the infoValue field is omitted (RFC-compliant "value absent").
func marshalInfoTypeAndValue(oid asn1.ObjectIdentifier, valueDER []byte) ([]byte, error) {
	if len(valueDER) == 0 {
		return asn1.Marshal(struct {
			InfoType asn1.ObjectIdentifier
		}{oid})
	}
	return asn1.Marshal(struct {
		InfoType  asn1.ObjectIdentifier
		InfoValue asn1.RawValue
	}{oid, asn1.RawValue{FullBytes: valueDER}})
}

// marshalGenRepBody wraps the per-entry InfoTypeAndValue DERs in the
// GenRepContent SEQUENCE. The [22] PKIBody context wrapper is added by
// sendRawBody, matching the suite's [22] EXPLICIT GenRepContent encoding.
func marshalGenRepBody(entries [][]byte) ([]byte, error) {
	var content []byte
	for _, e := range entries {
		content = append(content, e...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// encodeCaCertsValue encodes CaCertsValue ::= SEQUENCE OF CMPCertificate.
func encodeCaCertsValue(certs []*x509.Certificate) ([]byte, error) {
	var content []byte
	for _, c := range certs {
		if c == nil {
			continue
		}
		content = append(content, c.Raw...) // each cert.Raw is already a SEQUENCE
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// encodeAlgIDList encodes SEQUENCE OF AlgorithmIdentifier from bare OIDs.
func encodeAlgIDList(oids ...asn1.ObjectIdentifier) ([]byte, error) {
	algs := make([]pkix.AlgorithmIdentifier, 0, len(oids))
	for _, o := range oids {
		algs = append(algs, pkix.AlgorithmIdentifier{Algorithm: o})
	}
	return asn1.Marshal(algs)
}

// encodeAlgID encodes a single AlgorithmIdentifier.
func encodeAlgID(oid asn1.ObjectIdentifier) ([]byte, error) {
	return asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oid})
}

// encodeUTF8Sequence encodes SEQUENCE OF UTF8String from the given tags.
func encodeUTF8Sequence(tags ...string) ([]byte, error) {
	var content []byte
	for _, t := range tags {
		d, err := asn1.MarshalWithParams(t, "utf8")
		if err != nil {
			return nil, err
		}
		content = append(content, d...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// encodeCrlsValue encodes CRLsValue ::= SEQUENCE OF CertificateList.
func encodeCrlsValue(crls []*x509.RevocationList) ([]byte, error) {
	var content []byte
	for _, c := range crls {
		if c == nil {
			continue
		}
		content = append(content, c.Raw...) // each CRL.Raw is a CertificateList SEQUENCE
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// encodeRootCaKeyUpdateValue encodes RootCaKeyUpdateValue (RFC 9483 §4.3.2):
//
//	RootCaKeyUpdateValue ::= SEQUENCE {
//	    newWithNew   CMPCertificate,
//	    newWithOld   [0] CMPCertificate OPTIONAL,
//	    oldWithNew   [1] CMPCertificate OPTIONAL }
func encodeRootCaKeyUpdateValue(out *services.RootCACertUpdateOutput) ([]byte, error) {
	if out == nil || out.NewWithNew == nil {
		return nil, fmt.Errorf("rootCaKeyUpdate requires newWithNew")
	}
	var content []byte
	content = append(content, out.NewWithNew.Raw...)
	if out.NewWithOld != nil {
		tagged, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      out.NewWithOld.Raw,
		})
		if err != nil {
			return nil, err
		}
		content = append(content, tagged...)
	}
	if out.OldWithNew != nil {
		tagged, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      out.OldWithNew.Raw,
		})
		if err != nil {
			return nil, err
		}
		content = append(content, tagged...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// encodeCertReqTemplateValue encodes CertReqTemplateValue (RFC 9483 §4.3.3):
//
//	CertReqTemplateValue ::= SEQUENCE {
//	    certTemplate CertTemplate,
//	    keySpec      Controls OPTIONAL }
//
// Lamassu imposes no template constraints, so only an (empty) CertTemplate is
// emitted; keySpec is omitted.
func encodeCertReqTemplateValue(out *services.CertReqTemplateOutput) ([]byte, error) {
	// An empty CertTemplate is an empty SEQUENCE.
	certTemplate, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      nil,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certTemplate,
	})
}
