package cmp

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
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
	oidItRevPassphrase    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 12} // RFC 4210bis §5.3.19.9
)

// The two certReqTemplate keySpec controls (RFC 4211 §6 arc
// 1.3.6.1.5.5.7.5.1.*, semantics in RFC 9480 §2.15 / RFC 9483 §4.3.3). They are
// NOT interchangeable and carry different value types:
//
//	id-regCtrl-algId     AlgIdCtrl ::= AlgorithmIdentifier
//	                     MAY identify any algorithm OTHER than rsaEncryption;
//	                     for id-ecPublicKey the parameters name the curve.
//	id-regCtrl-rsaKeyLen RsaKeyLenCtrl ::= INTEGER (1..MAX)
//	                     SHALL be used for rsaEncryption and carries the
//	                     intended modulus bit length.
var (
	oidRegCtrlAlgId     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 11}
	oidRegCtrlRsaKeyLen = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 12}
)

// oidECPublicKey and the named-curve OIDs used as the ECParameters namedCurve of
// an id-regCtrl-algId control (RFC 5480 §2.1.1.1), keyed by curve bit size. A
// bare id-ecPublicKey AlgorithmIdentifier is not enough — the parameters field
// is what tells the EE which curve to generate on.
var ecCurveOIDByBits = map[int]asn1.ObjectIdentifier{
	256: {1, 2, 840, 10045, 3, 1, 7}, // secp256r1 / prime256v1
	384: {1, 3, 132, 0, 34},          // secp384r1
	521: {1, 3, 132, 0, 35},          // secp521r1
}

// defaultAdvertisedRSAKeyLen is the modulus bit length advertised in an
// id-regCtrl-rsaKeyLen control when the profile accepts RSA without naming any
// specific sizes. 2048 is the smallest modulus still considered acceptable.
const defaultAdvertisedRSAKeyLen = 2048

// Algorithm OIDs advertised in signing/encryption key-pair-type and preferred
// symmetric-algorithm responses. The AES variants live under the NIST arc
// 2.16.840.1.101.3.4.1.* (RFC 3565 / RFC 5754).
var (
	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

// preferredSymmAlgOID maps the DMS-configured symmetric-algorithm choice to its
// AlgorithmIdentifier OID for the id-it-preferredSymmAlg response. Unknown or
// empty falls back to AES-256-CBC (the historical default).
func preferredSymmAlgOID(alg models.CMPPreferredSymmetricAlgorithm) asn1.ObjectIdentifier {
	switch alg {
	case models.CMPPreferredSymmetricAlgorithmAES128CBC:
		return oidAES128CBC
	case models.CMPPreferredSymmetricAlgorithmAES192CBC:
		return oidAES192CBC
	case models.CMPPreferredSymmetricAlgorithmAES256CBC:
		return oidAES256CBC
	case models.CMPPreferredSymmetricAlgorithmAES128GCM:
		return oidAES128GCM
	case models.CMPPreferredSymmetricAlgorithmAES192GCM:
		return oidAES192GCM
	case models.CMPPreferredSymmetricAlgorithmAES256GCM:
		return oidAES256GCM
	default:
		return oidAES256CBC
	}
}

// cmpSupportedLangTags is the set of BCP 47 language tags the CA is willing to
// negotiate for human-readable PKIFreeText (RFC 4210bis 5.3.19.13). English is
// the only language Lamassu emits status strings in, so it is the sole entry.
// Comparison is case-insensitive on the primary subtag (e.g. "en-US" matches
// "en"). Keep this in sync with the languages actually used in status strings.
var cmpSupportedLangTags = map[string]bool{
	"en": true,
}

// selectSupportedLangTag returns the first offered tag whose primary subtag is
// in cmpSupportedLangTags, preserving the EE's preference order (RFC 4210bis
// 5.3.19.13: the CA picks its preferred tag from the EE's list). The second
// return is false when none of the offered tags is supported, which the caller
// maps to a badRequest rejection.
func selectSupportedLangTag(offered []string) (string, bool) {
	for _, tag := range offered {
		primary := tag
		if i := strings.IndexByte(tag, '-'); i >= 0 {
			primary = tag[:i]
		}
		if cmpSupportedLangTags[strings.ToLower(strings.TrimSpace(primary))] {
			return tag, true
		}
	}
	return "", false
}

// genITAV is the decoded request InfoTypeAndValue. infoValue is OPTIONAL; an
// absent value leaves InfoValue at its zero RawValue (FullBytes == nil).
type genITAV struct {
	InfoType  asn1.ObjectIdentifier
	InfoValue asn1.RawValue `asn1:"optional"`
}

// handleGeneralMessage processes a genm (21) body and answers with a genp (22).
// Signature protection has already been verified by HandleCMP; sender/senderKID
// binding is intentionally not enforced for genm (see the dispatch in cmp.go).
func (r *cmpHttpRoutes) handleGeneralMessage(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.CMPEnrollmentSettings, signerCert *x509.Certificate) {
	itavs, err := decodeGenMsgContent(body.Bytes)
	if err != nil {
		lFunc.Errorf("genm: decode GenMsgContent: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "malformed GenMsgContent", dmsID, corecmp.PKIFailureInfoBadDataFormat)
		return
	}
	if len(itavs) == 0 {
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "empty GenMsgContent", dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}

	// RFC011 GENM.AccessPolicy: public_discovery answers unauthenticated genm;
	// require_signed answers only signature-protected requests. HandleCMP already
	// derives its wire-level protection requirement from this same policy (not the
	// enrollment auth_mode), so an unprotected require_signed genm is normally
	// rejected before reaching here; this stays as defense-in-depth.
	if enrollOpts.GENM.AccessPolicy == models.CMPGENMAccessPolicyRequireSigned && signerCert == nil {
		lFunc.Warnf("genm rejected: DMS requires signed general messages (GENM.AccessPolicy=require_signed)")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
			"general messages require a signature-protected request for this DMS", dmsID, corecmp.PKIFailureInfoNotAuthorized)
		return
	}

	respEntries := make([][]byte, 0, len(itavs))
	for _, itav := range itavs {
		lFunc.Infof("genm: infoType=%s", itav.InfoType.String())
		// RFC011 GENM.InformationTypes: refuse to answer an id-it type the DMS
		// has disabled.
		if !genmInfoTypeEnabled(enrollOpts.GENM.InformationTypes, itav.InfoType) {
			lFunc.Warnf("genm rejecting %s: information type disabled for this DMS", itav.InfoType.String())
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				fmt.Sprintf("general message information type %s is not enabled for this DMS", itav.InfoType.String()),
				dmsID, corecmp.PKIFailureInfoNotAuthorized)
			return
		}
		entryDER, rej := r.buildGenpEntry(ctx.Request.Context(), lFunc, dmsID, itav, enrollOpts.GENM.PreferredSymmetricAlgorithm)
		if rej != nil {
			lFunc.Warnf("genm: rejecting %s: %s", itav.InfoType.String(), rej.reason)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), rej.reason, dmsID, rej.failInfo)
			return
		}
		respEntries = append(respEntries, entryDER)
	}

	genRepDER, err := marshalGenRepBody(respEntries)
	if err != nil {
		lFunc.Errorf("genm: build genp body: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build genp response", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	r.sendRawBody(ctx, lFunc, header, corecmp.BodyTagGenRep, genRepDER, dmsID)
}

// genmInfoTypeEnabled reports whether the DMS permits answering a given id-it
// general-message information type (RFC011 GENM.InformationTypes). Types with no
// corresponding config field (e.g. revocation passphrase) are always allowed.
func genmInfoTypeEnabled(it models.CMPGENMInformationTypes, oid asn1.ObjectIdentifier) bool {
	switch oid.String() {
	case oidItCaCerts.String():
		return it.CACertificates
	case oidItRootCaCert.String():
		return it.RootCAUpdate
	case oidItCertReqTemplate.String():
		return it.CertificateRequestTemplate
	case oidItCurrentCRL.String():
		return it.CurrentCRL
	case oidItCrlStatusList.String():
		return it.CRLUpdate
	case oidItCaProtEncCert.String():
		// Lamassu does not provision a dedicated protocol-encryption certificate,
		// so buildGenpEntry can only answer with an absent infoValue. That is
		// still a valid answer — RFC 4210bis §5.3.19.1 makes the certificate
		// itself optional, and an absent value means "not available". Refusing
		// the whole genm instead (notAuthorized) is strictly worse: it turns a
		// legitimate capability query into an error message. So honour the
		// operator's toggle and let the absent-value response through.
		return it.ProtocolEncryptionCertificate
	case oidItRevPassphrase.String():
		// Hard-disabled for the time being. The revocation-passphrase handler
		// only accepts-and-acknowledges (RFC 4210bis §5.3.19.9) and is not wired
		// into the revocation path, so it is kept out of service until it does
		// something real. Without this explicit case it would fall through to
		// the default and be answered.
		return false
	case oidItSignKeyPairTypes.String():
		return it.SigningKeyTypes
	case oidItEncKeyPairTypes.String():
		return it.EncryptionKeyTypes
	case oidItPreferredSymmAlg.String():
		return it.PreferredSymmetricAlgorithm
	case oidItSuppLangTags.String():
		return it.SupportedLanguages
	default:
		return true
	}
}

// buildGenpEntry maps a single request InfoTypeAndValue to its genp response
// entry. Returns the DER of the response InfoTypeAndValue, or a rejection when
// the request violates the per-OID infoValue presence rule (RFC 9483 §4.3) or
// the underlying service call fails.
func (r *cmpHttpRoutes) buildGenpEntry(ctx context.Context, lFunc *logrus.Entry, dmsID string, itav genITAV, preferredSymmAlg models.CMPPreferredSymmetricAlgorithm) ([]byte, *cmpEnvelopeRejection) {
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
		reqIn := services.GetRootCACertUpdateInput{APS: dmsID}
		if hasValue {
			// When present, the request infoValue is the EE's currently-trusted
			// root CA certificate (CMPCertificate); decode it so the service can
			// decide whether a newer root exists. A malformed value is ignored
			// rather than rejected — it remains a valid "is there an update?" query.
			if cur, perr := x509.ParseCertificate(itav.InfoValue.FullBytes); perr == nil {
				reqIn.CurrentRootCert = cur
			}
		}
		out, err := r.svc.LWCGetRootCACertUpdate(ctx, reqIn)
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
		// Unlike the other support messages the request value is MANDATORY:
		// id-it-crlStatusList carries SEQUENCE SIZE (1..MAX) OF CRLStatus
		// (RFC 9480 §2.16), naming which CRLs the EE wants and how fresh its
		// copies already are. Without it there is no request to answer.
		if !hasValue {
			return nil, rejBadRequest("id-it-crlStatusList request requires a CRLStatus value")
		}
		statuses, err := decodeCRLStatusList(itav.InfoValue.FullBytes)
		if err != nil {
			return nil, rejBadRequest("malformed crlStatusList value: " + err.Error())
		}
		if len(statuses) == 0 {
			return nil, rejBadRequest("crlStatusList must carry at least one CRLStatus")
		}

		// One CRL per requested source, and only when it is genuinely newer than
		// what the EE already holds (RFC 9483 §4.3.4: "the server shall only
		// provide those CRLs that are more recent"). A source with nothing newer
		// contributes no entry; when that is true of every source the response
		// value is absent, which is how the EE learns it is already up to date.
		var crls []*x509.RevocationList
		for _, st := range statuses {
			crl, err := r.svc.LWCGetCRL(ctx, services.GetCMPCRLInput{
				APS:               dmsID,
				IssuerName:        st.IssuerName,
				IssuerRawDN:       st.IssuerRawDN,
				CurrentThisUpdate: st.ThisUpdate,
			})
			if err != nil {
				return nil, rejSystemFailure("CRL update retrieval: " + err.Error())
			}
			if crl != nil {
				crls = append(crls, crl)
			}
		}

		respOID = oidItCrls
		if len(crls) > 0 {
			v, encErr := encodeCrlsValue(crls)
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
		v, err := encodeAlgIDList(corecmp.OIDRSAEncryption(), corecmp.OIDECPublicKey())
		if err != nil {
			return nil, rejSystemFailure("cannot encode signKeyPairTypes")
		}
		respOID, respVal = oidItSignKeyPairTypes, v

	case oidItEncKeyPairTypes.String(): // 5.3.19.3 Encryption/Key Agreement Key Pair Types
		if hasValue {
			return nil, rejBadRequest("id-it-encKeyPairTypes request infoValue MUST be absent")
		}
		v, err := encodeAlgIDList(corecmp.OIDRSAEncryption())
		if err != nil {
			return nil, rejSystemFailure("cannot encode encKeyPairTypes")
		}
		respOID, respVal = oidItEncKeyPairTypes, v

	case oidItPreferredSymmAlg.String(): // 5.3.19.4 Preferred Symmetric Algorithm
		if hasValue {
			return nil, rejBadRequest("id-it-preferredSymmAlg request infoValue MUST be absent")
		}
		v, err := encodeAlgID(preferredSymmAlgOID(preferredSymmAlg))
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
		// RFC 4210bis 5.3.19.13: the CA selects the single language tag it
		// prefers from the EE's offered list. When NONE of the offered tags is
		// one the CA supports, it MUST reject the request (badRequest) rather
		// than echo back an unsupported tag — otherwise the EE would believe a
		// language it cannot use was negotiated.
		chosen, ok := selectSupportedLangTag(tags)
		if !ok {
			return nil, rejBadRequest("none of the offered language tags are supported")
		}
		v, encErr := encodeUTF8Sequence(chosen)
		if encErr != nil {
			return nil, rejSystemFailure("cannot encode supportedLangTags")
		}
		respOID, respVal = oidItSuppLangTags, v

	case oidItRevPassphrase.String(): // RFC 4210bis §5.3.19.9 Revocation Passphrase
		// The EE hands over a passphrase (confidentiality-protected, typically
		// PWRI-encrypted) that MAY later authorize revocation without the
		// original credential. Lamassu does not wire it into the revocation
		// path yet, but per the RFC the CA only MUST accept and MAY acknowledge
		// — it need not decrypt or store the passphrase to be compliant. The
		// request infoValue MUST be present (there is nothing to hand over
		// otherwise); the response carries the same infoType with an absent
		// infoValue (acknowledgment only).
		if !hasValue {
			return nil, rejBadRequest("id-it-revPassphrase request requires a value")
		}
		respOID = oidItRevPassphrase

	default:
		return nil, &cmpEnvelopeRejection{
			reason:   "unsupported genm infoType " + itav.InfoType.String(),
			failInfo: corecmp.PKIFailureInfoBadRequest,
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
	return &cmpEnvelopeRejection{reason: reason, failInfo: corecmp.PKIFailureInfoBadRequest}
}

func rejSystemFailure(reason string) *cmpEnvelopeRejection {
	return &cmpEnvelopeRejection{reason: reason, failInfo: corecmp.PKIFailureInfoSystemFailure}
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

// crlStatusEntry is one decoded CRLStatus from a crlStatusList request.
type crlStatusEntry struct {
	// IssuerRawDN is the DER of the issuer's RDNSequence when the source is an
	// issuer [1] GeneralNames carrying a directoryName. Nil for a dpn source or
	// any GeneralNames without a directoryName, in which case the service falls
	// back to the DMS enrollment CA.
	IssuerRawDN []byte
	// IssuerName renders IssuerRawDN for logging; empty when absent/unparseable.
	IssuerName string
	// ThisUpdate is the thisUpdate of the CRL the EE already holds. Zero when
	// absent, meaning the EE holds no copy and any CRL is newer.
	ThisUpdate time.Time
}

// decodeCRLStatusList parses the id-it-crlStatusList request value
// (RFC 9480 §2.16):
//
//	SEQUENCE SIZE (1..MAX) OF CRLStatus
//	CRLStatus ::= SEQUENCE { source CRLSource, thisUpdate Time OPTIONAL }
//	CRLSource ::= CHOICE { dpn [0] DistributionPointName, issuer [1] GeneralNames }
//
// The CMP ASN.1 module uses EXPLICIT TAGS, so [0]/[1] wrap their content rather
// than replacing its tag — an issuer source is [1] { SEQUENCE OF GeneralName }.
//
// A dpn source is deliberately NOT resolved: RFC 9483 §4.3.4 is explicit that a
// DistributionPointName is an internal pointer to a CRL the server already has,
// never an instruction to go fetch from that location. Such an entry decodes
// with a nil IssuerRawDN and the service answers from the DMS default.
func decodeCRLStatusList(valueDER []byte) ([]crlStatusEntry, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(valueDER, &outer); err != nil {
		return nil, err
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("crlStatusList must be a SEQUENCE OF CRLStatus")
	}

	var out []crlStatusEntry
	rest := outer.Bytes
	for len(rest) > 0 {
		var status asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &status)
		if err != nil {
			return nil, fmt.Errorf("CRLStatus: %w", err)
		}
		if status.Class != asn1.ClassUniversal || status.Tag != asn1.TagSequence {
			return nil, fmt.Errorf("CRLStatus must be a SEQUENCE")
		}

		entry, err := decodeCRLStatus(status.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// decodeCRLStatus parses the content of a single CRLStatus SEQUENCE.
func decodeCRLStatus(content []byte) (crlStatusEntry, error) {
	var entry crlStatusEntry

	var source asn1.RawValue
	rest, err := asn1.Unmarshal(content, &source)
	if err != nil {
		return entry, fmt.Errorf("CRLSource: %w", err)
	}
	if source.Class != asn1.ClassContextSpecific || (source.Tag != 0 && source.Tag != 1) {
		return entry, fmt.Errorf("CRLSource must be dpn [0] or issuer [1], got class=%d tag=%d", source.Class, source.Tag)
	}
	if source.Tag == 1 {
		// issuer [1] GeneralNames ::= SEQUENCE OF GeneralName. Pick the
		// directoryName [4] alternative, whose content is the RDNSequence DER we
		// match subjects on.
		if raw, name := directoryNameFromGeneralNames(generalNamesContent(source.Bytes)); raw != nil {
			entry.IssuerRawDN, entry.IssuerName = raw, name
		}
	}

	// thisUpdate Time OPTIONAL — a CHOICE of UTCTime / GeneralizedTime, so it
	// appears with its own universal tag rather than a context tag.
	if len(rest) > 0 {
		var t asn1.RawValue
		if _, err := asn1.Unmarshal(rest, &t); err != nil {
			return entry, fmt.Errorf("CRLStatus thisUpdate: %w", err)
		}
		switch t.Tag {
		case asn1.TagUTCTime, asn1.TagGeneralizedTime:
			var parsed time.Time
			if _, err := asn1.Unmarshal(t.FullBytes, &parsed); err != nil {
				return entry, fmt.Errorf("CRLStatus thisUpdate: %w", err)
			}
			entry.ThisUpdate = parsed
		default:
			return entry, fmt.Errorf("CRLStatus thisUpdate must be UTCTime or GeneralizedTime, got tag %d", t.Tag)
		}
	}
	return entry, nil
}

// generalNamesContent normalizes the content of a CRLSource issuer [1] field to
// the bare concatenation of GeneralName TLVs.
//
// The CMP module uses EXPLICIT TAGS, so [1] WRAPS the GeneralNames SEQUENCE
// rather than replacing its tag — which is what openssl emits, and means the
// GeneralName entries sit one level deeper than the context tag. An
// IMPLICIT-tagged encoder would instead put them directly in the [1] content.
// Both are accepted here: this is exactly the kind of detail implementations
// disagree on, and being strict buys nothing when the two are trivially
// distinguishable by whether the content is a single universal SEQUENCE.
func generalNamesContent(sourceBytes []byte) []byte {
	var inner asn1.RawValue
	rest, err := asn1.Unmarshal(sourceBytes, &inner)
	if err == nil && len(rest) == 0 && inner.Class == asn1.ClassUniversal && inner.Tag == asn1.TagSequence {
		return inner.Bytes // EXPLICIT: unwrap the GeneralNames SEQUENCE
	}
	return sourceBytes // IMPLICIT: already the GeneralName TLVs
}

// directoryNameFromGeneralNames scans a GeneralNames content block for the first
// directoryName [4] entry and returns its RDNSequence DER plus a rendered form
// for logging. Both are nil/empty when no directoryName is present — the other
// GeneralName alternatives (dNSName, URI, ...) do not identify a CA subject and
// so give us nothing to match against.
func directoryNameFromGeneralNames(content []byte) ([]byte, string) {
	rest := content
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &gn)
		if err != nil {
			return nil, ""
		}
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 4 {
			continue
		}
		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(gn.Bytes, &rdn); err != nil {
			return nil, ""
		}
		var name pkix.Name
		name.FillFromRDNSequence(&rdn)
		return gn.Bytes, name.String()
	}
	return nil, ""
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
// certTemplate advertises the CA-set validity (CertTemplate validity [4]) and,
// when the profile mandates them, the subject ([5], an EXPLICITly tagged Name —
// RFC 4211 §5) and keyUsage/extKeyUsage extensions ([9]); keySpec advertises
// each accepted public-key algorithm as an id-regCtrl-algId control. Fields the
// CA does not constrain are omitted; CertTemplate fields are emitted in
// ascending tag order (validity [4] before subject [5] before extensions [9])
// as DER requires.
func encodeCertReqTemplateValue(out *services.CertReqTemplateOutput) ([]byte, error) {
	var certTemplateContent []byte
	if out != nil {
		// validity [4] is IMPLICIT over OptionalValidity ::= SEQUENCE {
		//   notBefore [0] Time OPTIONAL, notAfter [1] Time OPTIONAL }.
		// Time is a CHOICE (utcTime/generalTime), so [0]/[1] are EXPLICIT.
		if !out.NotAfter.IsZero() {
			validityField, err := encodeCertTemplateValidity(out.NotBefore, out.NotAfter)
			if err != nil {
				return nil, err
			}
			certTemplateContent = append(certTemplateContent, validityField...)
		}

		rawSubject := out.Subject.RawSubject
		if len(rawSubject) == 0 && len(out.Subject.Subject.ToRDNSequence()) > 0 {
			der, err := asn1.Marshal(out.Subject.Subject.ToRDNSequence())
			if err != nil {
				return nil, err
			}
			rawSubject = der
		}
		if len(rawSubject) > 0 {
			// subject is [5] Name; Name is a CHOICE, so the context tag is
			// constructed/explicit wrapping the RDNSequence DER.
			subjectField, err := asn1.Marshal(asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        5,
				IsCompound: true,
				Bytes:      rawSubject,
			})
			if err != nil {
				return nil, err
			}
			certTemplateContent = append(certTemplateContent, subjectField...)
		}

		// extensions [9] is IMPLICIT over Extensions ::= SEQUENCE OF Extension
		// (RFC 4211 §5) — matches parseCertTemplateExtensions on the request
		// side: the context tag directly replaces the SEQUENCE tag, so the
		// field content is the concatenation of individual Extension TLVs, not
		// those TLVs wrapped in an extra inner SEQUENCE.
		if out.KeyUsage != 0 || len(out.ExtKeyUsage) > 0 {
			var extsContent []byte
			if out.KeyUsage != 0 {
				ext, err := chelpers.GenerateKeyUsagePKIExtension(out.KeyUsage)
				if err != nil {
					return nil, err
				}
				extDER, err := asn1.Marshal(ext)
				if err != nil {
					return nil, err
				}
				extsContent = append(extsContent, extDER...)
			}
			if len(out.ExtKeyUsage) > 0 {
				ext, err := chelpers.GenerateExtendedKeyUsagePKIExtension(out.ExtKeyUsage)
				if err != nil {
					return nil, err
				}
				extDER, err := asn1.Marshal(ext)
				if err != nil {
					return nil, err
				}
				extsContent = append(extsContent, extDER...)
			}
			extensionsField, err := asn1.Marshal(asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        9,
				IsCompound: true,
				Bytes:      extsContent,
			})
			if err != nil {
				return nil, err
			}
			certTemplateContent = append(certTemplateContent, extensionsField...)
		}
	}
	certTemplate, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certTemplateContent,
	})
	if err != nil {
		return nil, err
	}

	content := certTemplate

	keySpec, err := encodeCertReqTemplateKeySpec(out)
	if err != nil {
		return nil, err
	}
	content = append(content, keySpec...)

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// encodeCertReqTemplateKeySpec builds the certReqTemplate keySpec value:
//
//	keySpec Controls ::= SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue
//
// advertising the public-key constraint the CA enforces. RFC 9480 §2.15 splits
// that constraint over two controls whose applicability is fixed by algorithm:
// rsaEncryption SHALL use id-regCtrl-rsaKeyLen (an INTEGER modulus bit length)
// and every other algorithm uses id-regCtrl-algId (an AlgorithmIdentifier, which
// MUST NOT be rsaEncryption). Since the value type differs, a single algorithm
// can never be expressed by both, and exactly ONE control is emitted here: when
// a profile accepts RSA and ECDSA alike, the RSA constraint is advertised
// because rsaKeyLen names a concrete minimum size, which is the more actionable
// of the two for an EE about to generate a key.
//
// Returns nil (keySpec omitted — it is OPTIONAL) when the profile constrains
// neither algorithm, which is the case whenever crypto enforcement is off.
func encodeCertReqTemplateKeySpec(out *services.CertReqTemplateOutput) ([]byte, error) {
	if out == nil {
		return nil, nil
	}

	var control []byte
	var err error
	switch {
	case slices.Contains(out.AllowedKeyAlgorithms, x509.RSA):
		control, err = encodeRSAKeyLenControl(out.AllowedRSAKeySizes)
	case slices.Contains(out.AllowedKeyAlgorithms, x509.ECDSA):
		control, err = encodeECAlgIDControl(out.AllowedECDSAKeySizes)
	default:
		return nil, nil
	}
	if err != nil || len(control) == 0 {
		return nil, err
	}

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      control,
	})
}

// encodeRSAKeyLenControl builds the id-regCtrl-rsaKeyLen AttributeTypeAndValue
// carrying the intended modulus bit length. The SMALLEST accepted size is
// advertised: the control states the length the EE should generate, so naming
// anything larger would reject keys the CA would in fact have accepted. An empty
// list means the profile accepts RSA without constraining the size, in which
// case the 2048-bit baseline is advertised rather than omitting the constraint
// entirely.
func encodeRSAKeyLenControl(allowedSizes []int) ([]byte, error) {
	keyLen := defaultAdvertisedRSAKeyLen
	if len(allowedSizes) > 0 {
		keyLen = slices.Min(allowedSizes)
	}
	value, err := asn1.Marshal(keyLen)
	if err != nil {
		return nil, err
	}
	return marshalControl(oidRegCtrlRsaKeyLen, value)
}

// encodeECAlgIDControl builds the id-regCtrl-algId AttributeTypeAndValue for
// ECDSA: an id-ecPublicKey AlgorithmIdentifier whose parameters are the
// ECParameters namedCurve choice (RFC 5480 §2.1.1.1). The parameters are
// mandatory in practice — without them the EE learns only "some EC key", not
// which curve — so a size with no known curve OID yields no control at all
// rather than a bare, unusable id-ecPublicKey. As with RSA the smallest accepted
// curve is advertised.
func encodeECAlgIDControl(allowedSizes []int) ([]byte, error) {
	curveBits := 256 // P-256 when the profile does not constrain the curve
	if len(allowedSizes) > 0 {
		curveBits = slices.Min(allowedSizes)
	}
	curveOID, ok := ecCurveOIDByBits[curveBits]
	if !ok {
		return nil, nil
	}
	curveParams, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, err
	}
	value, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  corecmp.OIDECPublicKey(),
		Parameters: asn1.RawValue{FullBytes: curveParams},
	})
	if err != nil {
		return nil, err
	}
	return marshalControl(oidRegCtrlAlgId, value)
}

// marshalControl wraps a keySpec control value in its AttributeTypeAndValue.
func marshalControl(oid asn1.ObjectIdentifier, valueDER []byte) ([]byte, error) {
	return asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oid, asn1.RawValue{FullBytes: valueDER}})
}

// encodeCertTemplateValidity encodes a CertTemplate validity [4] field:
//
//	validity [4] OptionalValidity
//	OptionalValidity ::= SEQUENCE { notBefore [0] Time OPTIONAL, notAfter [1] Time OPTIONAL }
//	Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
//
// [4] is IMPLICIT over the SEQUENCE (its tag replaces the SEQUENCE tag), while
// notBefore [0] / notAfter [1] are EXPLICIT because Time is a CHOICE and a
// CHOICE cannot be implicitly tagged. Each Time is a UTCTime for years
// 1950–2049 and a GeneralizedTime otherwise (RFC 5280 §4.1.2.5).
func encodeCertTemplateValidity(notBefore, notAfter time.Time) ([]byte, error) {
	explicitTime := func(tag int, t time.Time) ([]byte, error) {
		timeDER, err := encodeChoiceTime(t)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        tag,
			IsCompound: true,
			Bytes:      timeDER,
		})
	}

	var content []byte
	if !notBefore.IsZero() {
		nb, err := explicitTime(0, notBefore)
		if err != nil {
			return nil, err
		}
		content = append(content, nb...)
	}
	na, err := explicitTime(1, notAfter)
	if err != nil {
		return nil, err
	}
	content = append(content, na...)

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      content,
	})
}

// encodeChoiceTime encodes a single ASN.1 Time CHOICE value, selecting UTCTime
// vs GeneralizedTime by RFC 5280's year boundary.
func encodeChoiceTime(t time.Time) ([]byte, error) {
	t = t.UTC()
	if t.Year() >= 1950 && t.Year() < 2050 {
		return asn1.MarshalWithParams(t, "utc")
	}
	return asn1.MarshalWithParams(t, "generalized")
}
