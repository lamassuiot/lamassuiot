package cmp

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers/cmp/internal/kga"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	software "github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

// This file owns the enrollment pipeline shared by ir/cr/kur:
//
//   handleEnrollment(variant) → issueAndStore | deferForApproval
//
// It is split out of cmp.go so the HTTP dispatcher (cmp.go) stays a
// dispatcher: tag → service → response. All policy (workflow selection,
// duplicate-tx detection, supersession, implicit-confirm negotiation,
// WFX state emission for the enrollment lifecycle) lives here (audit A2).

// handleEnrollment is the merged ir/cr/kur dispatcher (audit A3). The three
// enrollment bodies share the same skeleton — decode CertReqMessage, validate
// the proof of possession, emit the Validated WFX transition, hand off to
// issueAndStore — but differ in how POPO is established and in the response
// body tag. Those differences are captured in enrollmentVariant rather than
// duplicated across two handlers.
// cmpProofOfPossessionFor selects the ir or cr ProofOfPossession policy
// (RFC011) by body tag. Only meaningful when called from the ir/cr inner-POPO
// path (verifyInnerPOPO); kur never reaches it.
func cmpProofOfPossessionFor(o *models.EnrollmentOptionsLWCRFC9483, tag int) models.CMPProofOfPossession {
	if tag == corecmp.BodyTagCR {
		return o.CR.ProofOfPossession
	}
	return o.IR.ProofOfPossession
}

func popoMethodAllowed(p models.CMPProofOfPossession, method models.CMPPOPOMethod) bool {
	for _, m := range p.AllowedMethods {
		if m == method {
			return true
		}
	}
	return false
}

func (r *cmpHttpRoutes) handleEnrollment(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483, variant enrollmentVariant, signerCert *x509.Certificate) {
	// KUR-only pre-check: RFC 9483 §4.1.3 ties POPO to the message-level
	// protection because the EE must sign with the cert being updated. For
	// ir/cr the inner POPO is checked below; for kur an absent protection
	// algorithm is itself a POPO failure.
	if variant.requireMessageProtectionForPOPO && enrollOpts.EnforcePOPO {
		if len(header.ProtectionAlg.Algorithm) == 0 {
			lFunc.Warnf("kur: POPO enforcement requires message-level protection (RFC 9483 §4.1.3)")
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				"KUR requires message-level signature protection as proof of possession (RFC 9483 §4.1.3)",
				dmsID, corecmp.PKIFailureInfoBadPOP)
			return
		}
	}

	respTag := variant.respTagFor(body.Tag)

	req, err := corecmp.DecodeFirstCertReq(body.Bytes)
	if err != nil {
		var certRej *corecmp.CertRequestRejection
		if errors.As(err, &certRej) {
			// Cert-request-level rejection: respond with ip/cp body per RFC 9483 §4.1.
			lFunc.Warnf("%s: cert request rejected: %v", variant.logPrefix, err)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, certRej)
		} else {
			lFunc.Errorf("%s: decode CertReqMessage: %v", variant.logPrefix, err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "malformed CertReqMessage", dmsID, corecmp.PKIFailureInfoBadDataFormat)
		}
		return
	}

	// RFC 9483 §4.1.6 central key generation: the request carries no usable
	// public key and no POPO, so the server generates the key pair and returns it
	// encrypted in the response. This diverges from the normal issue-from-CSR
	// pipeline (no client key ⇒ no POPO, key/template checks below don't apply),
	// so it is handled entirely by handleKGAEnrollment.
	if req.ForKGA {
		r.handleKGAEnrollment(ctx, lFunc, header, req, dmsID, respTag, body.Tag, enrollOpts, variant.enrollFn(r, dmsID), signerCert)
		return
	}

	// Reject a weak RSA key up front: it is a defective CertTemplate
	// (badCertTemplate), not a proof-of-possession failure. This must run before
	// POPO verification because Go refuses to even verify a 512-bit RSA POPO
	// signature ("512-bit keys are insecure"), which would otherwise surface as a
	// misleading badPOP. Applies to ir/cr/kur alike (kur skips inner POPO).
	//
	// Oversized RSA keys are rejected symmetrically: a modulus far above any
	// practical size (e.g. 18000-bit) is a defective CertTemplate and a
	// resource-exhaustion vector (verifying such a signature is itself
	// expensive). Both bounds are enforced by rejectWeakOrOversizedRSAKey.
	if rej := rejectWeakOrOversizedRSAKey(req.PublicKeyDER, variant.logPrefix, req.CertReqID, lFunc); rej != nil {
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	// RFC 9483 §5.2.3: raVerified MUST NOT be used in a kur — the proof of
	// possession for a key update is the message protection made with the very
	// certificate being updated, and no RA (trusted or not) can assert that on
	// the EE's behalf. notAuthorized mirrors the ir/cr mapping for an entity
	// asserting raVerified it has no right to use.
	if variant.isReenrollment && req.POPORaw.Class == asn1.ClassContextSpecific && req.POPORaw.Tag == 0 && len(req.POPORaw.FullBytes) > 0 {
		lFunc.Warnf("kur: raVerified POPO is not permitted in a key update request (RFC 9483 §5.2.3)")
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "raVerified POPO is not permitted in a key update request (RFC 9483 §5.2.3)",
			FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
		})
		return
	}

	// Inner-POPO verification is meaningful for ir/cr (RFC 9483 §4.1 /
	// RFC 4211 §4.1 clause 3). For kur, the protection certificate proves
	// possession of the key being updated, so a separate inner-POPO check
	// would be redundant (and is omitted by RFC 9483 §4.1.3).
	// RFC011: ir/cr each have their own POPO policy (which methods are
	// accepted, and whether POPO is mandatory). body.Tag selects the block —
	// this function is the shared ir/cr/kur pipeline, but verifyInnerPOPO below
	// is only true for ir/cr, so body.Tag is always IR or CR inside it.
	popoPolicy := cmpProofOfPossessionFor(enrollOpts, body.Tag)

	useEncrCert := false
	useChallengeResp := false
	if variant.verifyInnerPOPO {
		// keyEncipherment [2] / keyAgreement [3]: the "indirect" POP methods
		// (RFC 4210bis §5.2.8), where possession is proven by a subsequent
		// message rather than a signature over the CertRequest. Neither needs
		// verifyPOPO: encrCert's proof is the ability to decrypt the delivered
		// certificate, and challengeResp's is answering popdecc with the
		// decrypted random value — both handled after issuance-independent
		// validation (regToken, CertTemplate policy, ...) runs below, exactly
		// as for a normal signature POPO.
		if req.POPORaw.Class == asn1.ClassContextSpecific && (req.POPORaw.Tag == 2 || req.POPORaw.Tag == 3) {
			switch classifyPOPOIndirect(req.POPORaw.Bytes) {
			case popoIndirectEncrCert:
				if !popoMethodAllowed(popoPolicy, models.CMPPOPOMethodEncryptedCertificate) {
					lFunc.Warnf("%s: encrCert POPO rejected: not permitted by DMS POPO allow-list", variant.logPrefix)
					r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
						CertReqID:   req.CertReqID,
						Reason:      "encrypted-certificate proof of possession is not permitted for this DMS",
						FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
					})
					return
				}
				lFunc.Infof("%s: encrCert POPO — certificate will be delivered confidentiality-protected (RFC 4210bis §5.2.8.4)", variant.logPrefix)
				useEncrCert = true
			case popoIndirectChallengeResp:
				if !popoMethodAllowed(popoPolicy, models.CMPPOPOMethodChallengeResponse) {
					lFunc.Warnf("%s: challengeResp POPO rejected: not permitted by DMS POPO allow-list", variant.logPrefix)
					r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
						CertReqID:   req.CertReqID,
						Reason:      "challenge-response proof of possession is not permitted for this DMS",
						FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
					})
					return
				}
				lFunc.Infof("%s: challengeResp POPO — issuance deferred until popdecr (RFC 4210bis §5.2.8.3)", variant.logPrefix)
				useChallengeResp = true
			case popoIndirectUnsupported:
				// Fall through: verifyPOPO's default case rejects agreeMAC /
				// encryptedKey / malformed POPOPrivKey content with badPOP,
				// exactly as before this indirect-method support was added.
			}
		}

		if !useEncrCert && !useChallengeResp {
			// RFC 9483 §5.2.3.2: a trusted RA that modified the CertTemplate verifies
			// the EE's proof-of-possession itself and sets popo = raVerified. lamassu
			// honours that only when the message-protection signer is a designated RA
			// (carries id-kp-cmcRA) AND that signer chain-validates against a CA this
			// DMS trusts (LWCValidateRASigner). Chain validation is essential here:
			// LWCEnroll only validates the signer for CLIENT_CERTIFICATE auth modes —
			// for NO_AUTH/EXTERNAL_WEBHOOK DMSs it never inspects the protection cert
			// at all, so checking the EKU alone would let anyone mint a throwaway
			// self-signed certificate carrying id-kp-cmcRA and skip POPO entirely.
			signer := signerCert
			isRAVerified := req.POPORaw.Class == asn1.ClassContextSpecific && req.POPORaw.Tag == 0 && len(req.POPORaw.FullBytes) > 0
			trustedRA := false
			if isRAVerified && signer != nil && popoMethodAllowed(popoPolicy, models.CMPPOPOMethodTrustedRA) {
				if validator, ok := r.svc.(services.LightweightCMPRAValidator); ok {
					if vErr := validator.LWCValidateRASigner(ctx.Request.Context(), dmsID, signer); vErr != nil {
						lFunc.Warnf("%s: raVerified POPO rejected: signer CN=%s is not a trusted PKI management entity: %v",
							variant.logPrefix, signer.Subject.CommonName, vErr)
					} else {
						trustedRA = true
					}
				} else {
					lFunc.Errorf("%s: raVerified POPO rejected: RA signer validation is not available", variant.logPrefix)
				}
			}

			// RFC011: a signature POPO (tag 1) requires "signature" on the
			// operation's allow-list. Rejected before verifyPOPO so the failure is
			// notAuthorized (policy) rather than badPOP (cryptographic failure).
			isSignaturePOPO := req.POPORaw.Class == asn1.ClassContextSpecific && req.POPORaw.Tag == 1
			if !trustedRA && isSignaturePOPO && !popoMethodAllowed(popoPolicy, models.CMPPOPOMethodSignature) {
				lFunc.Warnf("%s: signature POPO rejected: not permitted by DMS POPO allow-list", variant.logPrefix)
				r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
					CertReqID:   req.CertReqID,
					Reason:      "signature proof of possession is not permitted for this DMS",
					FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
				})
				return
			}

			if trustedRA {
				lFunc.Infof("%s: accepting raVerified POPO from trusted RA (id-kp-cmcRA) CN=%s", variant.logPrefix, signer.Subject.CommonName)
				// RFC011 POPO.Required override of the legacy EnforcePOPO flag.
			} else if err := verifyPOPO(req.CertReqDER, req.POPORaw, req.PublicKeyDER, popoPolicy.Required); err != nil {
				// An EE asserting raVerified is notAuthorized (RFC 9483 §4.1); every
				// other POPO failure is badPOP.
				failBit := corecmp.PKIFailureInfoBadPOP
				if errors.Is(err, errPOPORAVerifiedFromEE) {
					failBit = corecmp.PKIFailureInfoNotAuthorized
				}
				lFunc.Warnf("%s: POPO verification failed: %v", variant.logPrefix, err)
				r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
					CertReqID:   req.CertReqID,
					Reason:      fmt.Sprintf("proof of possession verification failed: %v", err),
					FailInfoBit: failBit,
				})
				return
			}
		}
	}

	// RFC 9483 §4.1.3 / RFC 4211 §6.2: when a KUR carries the optional
	// id-regCtrl-oldCertID control, it MUST reference the certificate being
	// updated. We validate it against the protection (signer) certificate — the
	// EE's current cert — and reject with badCertId in a kup CertRepMessage on
	// mismatch, before the service-layer signer binding runs.
	if variant.isReenrollment && req.OldCertID != nil {
		if signer := signerCert; signer != nil {
			if rej := validateOldCertID(req, signer); rej != nil {
				lFunc.Warnf("kur: oldCertId mismatch: %s", rej.Reason)
				r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
				return
			}
		}
	}

	// RFC 4211 registration-control validation. Structurally-invalid
	// id-regCtrl-pkiPublicationInfo controls (§6.3) and an id-regInfo-certReq
	// alternate CertRequest whose public key differs from the primary request
	// (§7.2) are rejected in an ip/cp body before issuance. oldCertID is
	// handled above (KUR cert-to-update reference) and regToken below
	// (one-time-use, RFC 4211 §6.1 — see req.RegToken / HasSeenRegToken).
	//
	// RFC011: IR.authenticator_control.mode (disabled/optional/required) gates
	// on the control's mere PRESENCE, independent of whether ExpectedAuthenticator
	// is configured. Scoped to ir only — CMPCRSettings has no such field, so cr
	// (and kur, which shares this code path) keep the unconditional check below.
	if body.Tag == corecmp.BodyTagIR {
		present := corecmp.HasAuthenticatorControl(req.ControlsDER)
		mode := enrollOpts.IR.AuthenticatorControl.Mode
		if mode == models.CMPControlModeDisabled && present {
			lFunc.Warnf("%s: authenticator control rejected: disabled for this DMS (IR.AuthenticatorControl.Mode=disabled)", variant.logPrefix)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
				CertReqID:   req.CertReqID,
				Reason:      "the authenticator control is not accepted for this DMS",
				FailInfoBit: corecmp.PKIFailureInfoBadRequest,
			})
			return
		}
		if mode == models.CMPControlModeRequired && !present {
			lFunc.Warnf("%s: authenticator control rejected: required but absent (IR.AuthenticatorControl.Mode=required)", variant.logPrefix)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
				CertReqID:   req.CertReqID,
				Reason:      "the authenticator control is required for this DMS",
				FailInfoBit: corecmp.PKIFailureInfoBadRequest,
			})
			return
		}
	}

	// id-regCtrl-authenticator (§6.2) is validated against the DMS's
	// EnrollmentOptionsLWCRFC9483.ExpectedAuthenticator when configured — a
	// pre-shared, non-cryptographic answer (e.g. a security-question response)
	// distinct from regToken's one-time-use semantics. When the DMS has not
	// configured an expected answer, the control is accepted unvalidated.
	if rej := corecmp.ValidateAuthenticatorControl(req.CertReqID, req.ControlsDER, enrollOpts.ExpectedAuthenticator); rej != nil {
		lFunc.Warnf("%s: authenticator control rejected: %s", variant.logPrefix, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}
	if rej := corecmp.ValidatePKIPublicationInfoControls(req.CertReqID, req.ControlsDER); rej != nil {
		lFunc.Warnf("%s: pkiPublicationInfo control rejected: %s", variant.logPrefix, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}
	if rej := corecmp.ValidateAltCertReqPublicKey(req.CertReqID, req.RegInfoDER, req.PublicKeyDER); rej != nil {
		lFunc.Warnf("%s: alt CertReq rejected: %s", variant.logPrefix, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}
	// RFC 4211 §7.2: once the alternate CertRequest's public key has been
	// validated against the primary request above, its requested extensions —
	// not the primary CertTemplate's — govern issuance. This lets an RA modify
	// what gets certified (e.g. KeyUsage) while the EE's POPO, computed over the
	// primary CertRequest, stays valid. Applied BEFORE the CertTemplate policy
	// check below so that check (CA-cert / keyCertSign rejection) evaluates the
	// extensions that will actually be issued.
	if altExts := corecmp.AltCertReqExtensions(req.RegInfoDER); altExts != nil {
		req.Extensions = altExts
	}

	// RFC011: IR.registration_token.mode (disabled/optional/required) gates on
	// presence — regToken values are provisioned out-of-band (never part of DMS
	// config, see RFC011), so this only controls whether the control is
	// accepted/mandatory at all. Scoped to ir only, same rationale as
	// authenticator_control above.
	if body.Tag == corecmp.BodyTagIR {
		mode := enrollOpts.IR.RegistrationToken.Mode
		if mode == models.CMPControlModeDisabled && req.RegToken != "" {
			lFunc.Warnf("%s: regToken control rejected: disabled for this DMS (IR.RegistrationToken.Mode=disabled)", variant.logPrefix)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
				CertReqID:   req.CertReqID,
				Reason:      "the regToken control is not accepted for this DMS",
				FailInfoBit: corecmp.PKIFailureInfoBadRequest,
			})
			return
		}
		if mode == models.CMPControlModeRequired && req.RegToken == "" {
			lFunc.Warnf("%s: regToken control rejected: required but absent (IR.RegistrationToken.Mode=required)", variant.logPrefix)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
				CertReqID:   req.CertReqID,
				Reason:      "the regToken control is required for this DMS",
				FailInfoBit: corecmp.PKIFailureInfoBadRequest,
			})
			return
		}
	}

	// RFC 4211 §6.1: a regToken is one-time-use — reject a request presenting a
	// value already carried by an earlier transaction under this DMS.
	if req.RegToken != "" {
		seen, err := r.store.HasSeenRegToken(ctx.Request.Context(), dmsID, req.RegToken)
		if err != nil {
			lFunc.Errorf("%s: check regToken: %v", variant.logPrefix, err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "internal error", dmsID, corecmp.PKIFailureInfoSystemFailure)
			return
		}
		if seen {
			lFunc.Warnf("%s: regToken already used", variant.logPrefix)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
				CertReqID:   req.CertReqID,
				Reason:      "the regToken control was already used (RFC 4211 §6.1)",
				FailInfoBit: corecmp.PKIFailureInfoBadRequest,
			})
			return
		}
	}

	// CertTemplate policy enforcement (RFC 9483 §5 / RFC 5280 §4.2.1.9). Lamassu
	// only issues end-entity certificates over CMP, so a request for a CA
	// certificate (BasicConstraints cA=TRUE or the keyCertSign KeyUsage) or a
	// malformed BasicConstraints (pathLenConstraint present without cA=TRUE) is
	// rejected here — before issuance — with the appropriate failInfo bit.
	if rej := validateCertTemplatePolicy(req); rej != nil {
		lFunc.Warnf("%s: cert template policy rejected: %s", variant.logPrefix, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	deviceCN := extractCNFromSubjectDER(req.SubjectDER)
	wfxJobID := r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     hex.EncodeToString(header.TransactionID),
		DMSID:             dmsID,
		RequestType:       cmpTagToString(body.Tag),
		SubjectCommonName: deviceCN,
		State:             cmpwfx.CMPStateValidated,
		Metadata: map[string]any{
			"certReqId": req.CertReqID,
		},
	})

	params := issueParams{
		isReenrollment: variant.isReenrollment,
		requestTag:     body.Tag,
		respTag:        respTag,
		wfxJobID:       wfxJobID,
		useEncrCert:    useEncrCert,
		enroll:         variant.enrollFn(r, dmsID),
	}
	if useChallengeResp {
		r.handlePOPOChallenge(ctx, lFunc, &header, req, dmsID, enrollOpts, params)
		return
	}
	r.issueAndStore(ctx, lFunc, &header, req, dmsID, enrollOpts, params, signerCert)
}

// isRevokedCertError reports whether an enroll/reenroll error is the service's
// "certificate is revoked" rejection. The service returns these as plain
// fmt.Errorf strings (no sentinel), so we match on the substring; used to map
// the failure to PKIFailureInfo certRevoked instead of systemFailure.
func isRevokedCertError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "revoked")
}

// commitReenrollment invokes the service's deferred key-update commit: bind the
// confirmed certificate as the device's active identity and supersede the
// previous one (RFC 9483 §4.1.3). It is best-effort — a failure is logged but
// does not change the CMP protocol outcome, because the certificate has already
// been issued and delivered to the EE. The service is expected to implement
// services.LightweightCMPConfirmer; if it does not, the commit is skipped.
func (r *cmpHttpRoutes) commitReenrollment(ctx context.Context, lFunc *logrus.Entry, dmsID, certSerial string) {
	confirmer, ok := r.svc.(services.LightweightCMPConfirmer)
	if !ok {
		lFunc.Warnf("service does not implement LightweightCMPConfirmer; skipping key-update commit for cert %s", certSerial)
		return
	}
	if err := confirmer.LWCConfirmReenrollment(ctx, dmsID, certSerial); err != nil {
		lFunc.Errorf("could not commit confirmed key-update for cert %s: %v", certSerial, err)
	}
}

// enrollmentVariant captures the per-body-tag differences between ir/cr and
// kur so handleEnrollment can stay a single code path.
type enrollmentVariant struct {
	logPrefix                       string
	isReenrollment                  bool
	verifyInnerPOPO                 bool
	requireMessageProtectionForPOPO bool
	respTagFor                      func(requestTag int) int
	enrollFn                        func(r *cmpHttpRoutes, dmsID string) func(ctx context.Context, csr *x509.CertificateRequest, signerCert *x509.Certificate) (*x509.Certificate, error)
}

// enrollmentVariantInitial is the variant used for ir (0) and cr (2). The
// response tag depends on the request: ir → ip (1), cr → cp (3).
var enrollmentVariantInitial = enrollmentVariant{
	logPrefix:                       "ir/cr",
	isReenrollment:                  false,
	verifyInnerPOPO:                 true,
	requireMessageProtectionForPOPO: false,
	respTagFor: func(requestTag int) int {
		if requestTag == corecmp.BodyTagIR {
			return corecmp.BodyTagIP
		}
		return corecmp.BodyTagCP
	},
	enrollFn: func(r *cmpHttpRoutes, dmsID string) func(ctx context.Context, csr *x509.CertificateRequest, signerCert *x509.Certificate) (*x509.Certificate, error) {
		return func(ctx context.Context, csr *x509.CertificateRequest, signerCert *x509.Certificate) (*x509.Certificate, error) {
			return r.svc.LWCEnroll(ctx, csr, dmsID, signerCert)
		}
	},
}

// enrollmentVariantUpdate is the variant used for kur (7). Inner POPO is
// skipped because the message-level protection IS the POPO under RFC 9483
// §4.1.3; the response is always kup (8).
var enrollmentVariantUpdate = enrollmentVariant{
	logPrefix:                       "kur",
	isReenrollment:                  true,
	verifyInnerPOPO:                 false,
	requireMessageProtectionForPOPO: true,
	respTagFor: func(int) int {
		return corecmp.BodyTagKUP
	},
	enrollFn: func(r *cmpHttpRoutes, dmsID string) func(ctx context.Context, csr *x509.CertificateRequest, signerCert *x509.Certificate) (*x509.Certificate, error) {
		return func(ctx context.Context, csr *x509.CertificateRequest, signerCert *x509.Certificate) (*x509.Certificate, error) {
			return r.svc.LWCReenroll(ctx, csr, dmsID, signerCert)
		}
	},
}

// issueParams holds the per-operation differences between ir/cr and kur
// flows that the enrollment pipeline needs once decoding is done. Kept here
// alongside the only function that constructs it (handleEnrollment) and the
// only function that consumes it (issueAndStore).
type issueParams struct {
	isReenrollment bool
	requestTag     int
	respTag        int
	// wfxJobID is the WFX job UUID resolved at the Validated emit (the
	// first state emission that knows the device CN). Persisted onto the
	// cmp_transactions row so the management UI can deep-link directly to
	// the corresponding WFX workflow without a clientId-based round-trip.
	wfxJobID string
	// supersededCertSerial is set by issueAndStore for re-enrollments: the hex
	// serial of the kur's protection cert (the certificate being updated).
	// Persisted onto the transaction row so the pending-update check can lock
	// exactly that certificate until certConf or timeout (RFC 9483 §4.1.3).
	supersededCertSerial string
	// presetCSR, when non-nil, is used instead of synthesizing a CSR from the
	// firstCertReq fields. Set by the p10cr handler, whose body IS a real
	// signed PKCS#10 request — passing it through preserves the genuine
	// signature for downstream verification instead of the dummy one
	// buildSyntheticCSR emits.
	presetCSR *x509.CertificateRequest
	// useEncrCert is set when the request's inner POPO was keyEncipherment /
	// keyAgreement with subsequentMessage(encrCert) (RFC 4210bis §5.2.8.4): the
	// issued certificate must be delivered confidentiality-protected to the
	// requested public key instead of in the clear. See
	// buildEncryptedCertRepBody (cmp_popo_indirect.go).
	useEncrCert bool
	enroll      func(ctx context.Context, csr *x509.CertificateRequest, signerCert *x509.Certificate) (*x509.Certificate, error)
}

// issueAndStore is the shared enrollment pipeline: build CSR, check duplicate
// transactionID, call the CA, persist the ISSUED row for lost-response
// recovery, and respond with the cert.
func (r *cmpHttpRoutes) issueAndStore(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header *corecmp.RequestPKIHeader,
	req *corecmp.CertRequest,
	dmsID string,
	enrollOpts *models.EnrollmentOptionsLWCRFC9483,
	params issueParams,
	signerCert *x509.Certificate,
) {
	csr := params.presetCSR
	if csr == nil {
		var err error
		csr, err = corecmp.BuildSyntheticCSR(req.SubjectDER, req.PublicKeyDER, req.Extensions)
		if err != nil {
			lFunc.Errorf("synthesize CSR: %v", err)
			r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "cannot build CSR from CertTemplate", dmsID, corecmp.PKIFailureInfoBadCertTemplate)
			return
		}
	}
	lFunc = lFunc.WithField("cn", csr.Subject.CommonName)
	lFunc.Infof("enrollment request CN=%s (reenroll=%v)", csr.Subject.CommonName, params.isReenrollment)

	// RFC011: resolve the effective confirmation policy for THIS operation,
	// applying its policy_overrides.confirmation on top of the DMS-general
	// AcceptImplicit. Implicit confirmation is still only granted when the EE
	// also asked for it (id-it-implicitConfirm in generalInfo).
	op := cmpTagToString(params.requestTag)
	implicitConfirm := corecmp.HasImplicitConfirmOID(header.GeneralInfo) &&
		enrollOpts.EffectiveAcceptImplicit(op)
	header.ResponseImplicitConfirm = implicitConfirm

	// Early duplicate-transactionID check before calling the CA. The store is
	// guaranteed non-nil by NewCMPHttpRoutes.
	txHex := hex.EncodeToString(header.TransactionID)
	if exists, err := r.store.Exists(ctx.Request.Context(), txHex); err != nil {
		lFunc.Errorf("check existing txID: %v", err)
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "internal error", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	} else if exists {
		lFunc.Warnf("duplicate transactionID %s (pre-enroll check)", txHex)
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "transactionID already in use", dmsID, corecmp.PKIFailureInfoTransactionIDInUse)
		return
	}

	// RFC 9483 §4.1.3: a certificate MUST NOT start a second key-update while
	// its previous one is still awaiting certConf. The first KUR issues the new
	// certificate but defers the identity swap until confirmation, so a second
	// KUR protected with the same certificate in that window is rejected with
	// badRequest. Keyed on the protection (signer) cert's serial — the
	// certificate being updated — NOT the subject CN: a subject may legitimately
	// hold several certificates over time, and only the one under update is
	// locked. Once the prior KUR is confirmed (CONFIRMED) or rolled back on
	// timeout (REVOKED/expired) this check passes again.
	signer := signerCert
	if signer != nil && params.isReenrollment {
		params.supersededCertSerial = hex.EncodeToString(signer.SerialNumber.Bytes())
	}
	if params.supersededCertSerial != "" {
		inProgress, ipErr := r.store.HasUnconfirmedReenrollment(ctx.Request.Context(), dmsID, params.supersededCertSerial)
		if ipErr != nil {
			lFunc.Errorf("check in-progress reenrollment: %v", ipErr)
			r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "internal error", dmsID, corecmp.PKIFailureInfoSystemFailure)
			return
		}
		if inProgress {
			lFunc.Warnf("second KUR for cert %s while its previous key-update is unconfirmed", params.supersededCertSerial)
			r.rejectWithError(ctx, header, corecmp.PKIStatus(2),
				"a previous key-update for this certificate is still awaiting confirmation (RFC 9483 §4.1.3)",
				dmsID, corecmp.PKIFailureInfoBadRequest)
			return
		}
	}

	// Phased (admin-gated) workflow: do NOT issue now. Park the request in a
	// PENDING row carrying the synthesized CSR and reply with a "waiting"
	// response (RFC 9483 §4.4 / RFC 4210 §5.3.22). An administrator later
	// approves the transaction, which issues the cert and flips the row to
	// ISSUED; the EE retrieves it via pollReq.
	// RFC011: resolve the effective workflow for THIS operation, applying its
	// policy_overrides.workflow on top of the DMS-general Workflow.
	if enrollOpts.EffectiveWorkflow(op) == models.CMPWorkflowPhased {
		r.deferForApproval(ctx, lFunc, header, req, csr, dmsID, enrollOpts, params, txHex)
		return
	}

	// Detach from the HTTP connection so issuance completes even if the EE
	// drops the TCP connection mid-request.
	issuanceCtx := context.WithoutCancel(ctx.Request.Context())
	// RFC011: tag the context with which CMP body drove this issuance so
	// LWCEnroll (shared across ir/cr/p10cr) can apply CR-only settings.
	issuanceCtx = context.WithValue(issuanceCtx, core.LamassuContextKeyCMPOperation, op)
	cert, err := params.enroll(issuanceCtx, csr, signer)
	if err != nil {
		lFunc.Errorf("enroll failed: %v", err)
		// Map the few categories the service distinguishes to their RFC 9483
		// §3.5 failInfo bits; everything else is systemFailure (the broadest
		// "server-side inability to complete the request" bit, RFC 9810 §5.1.3).
		failBit := corecmp.PKIFailureInfoSystemFailure
		switch {
		case errors.Is(err, errs.ErrDMSEnrollInvalidCert):
			// Protection signer cert did not chain to any of the DMS's
			// ValidationCAs → the requester is not trusted.
			failBit = corecmp.PKIFailureInfoSignerNotTrusted
		case errors.Is(err, errs.ErrCMPDeviceOwnedByOtherDMS):
			// Signer is trusted and sender-matched, but the CSR claims a
			// device identity owned by a different DMS — RFC 9483 §3.5.
			failBit = corecmp.PKIFailureInfoNotAuthorized
		case errors.Is(err, errs.ErrCMPPendingUpdate):
			// Device has a key-update awaiting certConf: the open transaction
			// must complete or time out before new operations (RFC 9483 §4.1.3).
			failBit = corecmp.PKIFailureInfoBadRequest
		case errors.Is(err, errs.ErrCMPCertSuperseded):
			// Signer cert was replaced by a confirmed key-update — per
			// RFC 9483 §4.1.3 it can no longer authenticate operations.
			failBit = corecmp.PKIFailureInfoCertRevoked
		case errors.Is(err, errs.ErrCMPSignerNotActive):
			// kur signer binding failed: not the device's active cert and not
			// a recognised superseded one.
			failBit = corecmp.PKIFailureInfoBadRequest
		case errors.Is(err, errs.ErrCMPAbandonedUpdate):
			// ir/cr from a device that abandoned a key-update: it must recover
			// via kur, not initialization (RFC 9483 §4.1.3, sec-awareness).
			failBit = corecmp.PKIFailureInfoBadRequest
		case isRevokedCertError(err):
			failBit = corecmp.PKIFailureInfoCertRevoked
		}
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), err.Error(), dmsID, failBit)
		return
	}
	certSerial := hex.EncodeToString(cert.SerialNumber.Bytes())

	// Persist ISSUED row for lost-response recovery via pollReq.
	senderNonce, nonceErr := corecmp.NewNonce()
	if nonceErr != nil {
		lFunc.Errorf("nonce generation: %v", nonceErr)
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "internal error: nonce generation failed", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	// The response senderNonce is set on the wire even for implicit-confirm
	// exchanges: RFC 4210 §5.2.8 says no certConf will follow, but an EE MAY
	// still send one, and its recipNonce is then checked against tx.SentNonce
	// — the wire nonce and the persisted one must never diverge.
	header.ResponseSenderNonce = senderNonce
	// When implicit confirmation is granted, RFC 4210 §5.2.8 considers the
	// transaction successfully completed at IP delivery — no certConf will
	// follow. Persist the row directly as CONFIRMED so the confirmation
	// monitor does not revoke the cert at expires_at. The previous behaviour
	// was to insert ISSUED with a 5-minute window and never transition it,
	// which silently revoked every implicit-confirm enrollment.
	//
	// ConfirmedAt is set to EXACTLY CreatedAt (same time.Time value) — that
	// equality is the marker handleCertConf uses to distinguish a row that was
	// implicitly confirmed at issuance (a follow-up certConf is answered with
	// pkiConf) from one confirmed by an earlier certConf (a duplicate, answered
	// with error/certConfirmed).
	now := time.Now()
	initialState := models.CMPTransactionStateIssued
	var confirmedAt time.Time
	if implicitConfirm {
		initialState = models.CMPTransactionStateConfirmed
		confirmedAt = now
	}
	if storeErr := r.store.Insert(issuanceCtx, models.CMPTransaction{
		TransactionID:     txHex,
		DMSID:             dmsID,
		State:             initialState,
		CertSerialNumber:  certSerial,
		Certificate:       (*models.X509Certificate)(cert),
		IsReenrollment:    params.isReenrollment,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		WFXJobID:          params.wfxJobID,
		SentNonce:         hex.EncodeToString(senderNonce),
		ReceivedNonce:     hex.EncodeToString(header.SenderNonce),
		// For a kur, the protection cert is the certificate being updated
		// (RFC 9483 §4.1.3); recording its serial lets the pending-update check
		// lock exactly that certificate until certConf or timeout. Empty for
		// ir/cr and for unprotected updates.
		SupersededCertSerial: params.supersededCertSerial,
		RegToken:             req.RegToken,
		ConfirmedAt:          confirmedAt,
		ExpiresAt:            now.Add(confirmationTimeoutOrDefault(enrollOpts.ConfirmationTimeout)),
		CreatedAt:            now,
	}); storeErr != nil {
		if errors.Is(storeErr, errs.ErrCMPTransactionAlreadyExists) {
			lFunc.Warnf("duplicate transactionID %s", txHex)
			r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "transactionID already in use", dmsID, corecmp.PKIFailureInfoTransactionIDInUse)
			return
		}
		lFunc.Errorf("store transaction: %v", storeErr)
		lFunc.Warnf("failed to persist ISSUED row (cert delivered inline): %v", storeErr)
	}

	// Implicit confirmation: RFC 4210 §5.2.8 treats the transaction as complete
	// at KUP delivery — no certConf will follow — so commit the deferred
	// key-update now (bind the new cert as the device's active identity and
	// supersede the previous one). Explicit-confirm KURs commit in handleCertConf.
	if implicitConfirm && params.isReenrollment {
		r.commitReenrollment(issuanceCtx, lFunc, dmsID, certSerial)
	}

	// RFC 4210 §5.2.3 / RFC 9483 §5: if issuance dropped a critical extension
	// the CertTemplate requested (e.g. an unrecognized/invalid critical
	// extension our relaxed policy strips rather than rejects), the issued
	// certificate differs from the request, so the success status is
	// grantedWithMods (1) instead of accepted (0).
	statusCode := int(corecmp.PKIStatus(0))
	if requestedCriticalExtensionDropped(req.Extensions, cert) {
		lFunc.Infof("issued cert omits a requested critical extension; responding grantedWithMods")
		statusCode = 1
	}
	var certRepDER []byte
	var ecdhProtection *ecdhOriginator
	if params.useEncrCert {
		certRepDER, ecdhProtection, err = r.buildEncryptedCertRepBody(issuanceCtx, lFunc, dmsID, req.CertReqID, statusCode, cert, req.PublicKeyDER)
	} else {
		certRepDER, err = corecmp.MarshalCertRepBodyWithStatus(params.respTag, req.CertReqID, statusCode, cert.Raw)
	}
	if err != nil {
		lFunc.Errorf("build cert rep body: %v", err)
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "cannot build response", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	var responseDER []byte
	if ecdhProtection != nil {
		// keyAgreement encrCert recipient: keep the ECDH originator at
		// extraCerts[0] (the recipient derives the CEK from it) but sign the
		// outer message with the DMS's normal protection credentials so a
		// -srvcert-pinning client still accepts the sender.
		responseDER = r.sendKARIProtectedResponse(ctx, lFunc, *header, params.respTag, certRepDER, dmsID, ecdhProtection)
	} else {
		responseDER = r.sendRawBody(ctx, lFunc, *header, params.respTag, certRepDER, dmsID)
	}
	if len(responseDER) == 0 {
		return
	}
	r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     txHex,
		DMSID:             dmsID,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		CertSerialNumber:  certSerial,
		State:             cmpwfx.CMPStateResponded,
		Metadata: withCMPMessageB64(map[string]any{
			"certReqId":      req.CertReqID,
			"isReenrollment": params.isReenrollment,
			"responseType":   cmpTagToString(params.respTag),
		}, cmpMetadataResponseB64, responseDER),
	})
	finalState := cmpwfx.CMPStateAwaitingCertConf
	if implicitConfirm {
		finalState = cmpwfx.CMPStateLogicallyComplete
	}
	r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     txHex,
		DMSID:             dmsID,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		CertSerialNumber:  certSerial,
		State:             finalState,
		Metadata: map[string]any{
			"responseType":    cmpTagToString(params.respTag),
			"implicitConfirm": implicitConfirm,
		},
	})
}

// handleKGAEnrollment implements RFC 9483 §4.1.6 central key generation. The
// server generates the end-entity key pair, has the enrollment CA issue a
// certificate for it, wraps the private key in a CMS EnvelopedData(SignedData)
// (built by the backend KGA package), and returns both in the CertifiedKeyPair.
//
// The CMS recipient is the request's protection (signer) certificate: for KTRI
// the CEK is RSA-encrypted to its key; for KARI a fresh EC originator is used
// for ECDH against it. The compliance validator matches the CMS recipient /
// originator identifiers against the response's extraCerts[0] by SKI, so this
// handler places the correct certificate there (the EE cert for KTRI, the
// originator for KARI) while signing the response protection with a key it owns.
// ckgRecipientMethodAllowed reports whether the CKG key-delivery mechanism
// selected for this request (derived from the recipient key type) is permitted
// by the operation's CentralKeyGeneration.AllowedRecipientMethods (RFC011).
// requestTag selects the IR or CR block; an empty allow-list permits nothing.
func ckgRecipientMethodAllowed(o *models.EnrollmentOptionsLWCRFC9483, requestTag int, t kga.Technique) bool {
	var allowed []models.CMPCKGRecipientMethod
	if requestTag == corecmp.BodyTagCR {
		allowed = o.CR.CentralKeyGeneration.AllowedRecipientMethods
	} else {
		allowed = o.IR.CentralKeyGeneration.AllowedRecipientMethods
	}
	var want models.CMPCKGRecipientMethod
	switch t {
	case kga.TechniqueKTRI:
		want = models.CMPCKGRecipientMethodRSAKeyTransport
	case kga.TechniqueKARI:
		want = models.CMPCKGRecipientMethodECDHKeyAgreement
	default:
		return true
	}
	for _, a := range allowed {
		if a == want {
			return true
		}
	}
	return false
}

func (r *cmpHttpRoutes) handleKGAEnrollment(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header corecmp.RequestPKIHeader,
	req *corecmp.CertRequest,
	dmsID string,
	respTag, requestTag int,
	enrollOpts *models.EnrollmentOptionsLWCRFC9483,
	enroll func(ctx context.Context, csr *x509.CertificateRequest, signerCert *x509.Certificate) (*x509.Certificate, error),
	signerCert *x509.Certificate,
) {
	lFunc = lFunc.WithField("mode", "kga")

	// RFC 9483 §4.1.6 / story: operators opt in per DMS before a device can
	// have the server generate and deliver its private key. Checked before
	// anything else in this path — no key generation, CA issuance, or helper
	// certificate minting happens for a DMS that hasn't enabled this.
	if enrollOpts == nil || !enrollOpts.ServerKeyGenEnabled {
		lFunc.Warnf("kga: central key generation is not enabled for DMS '%s'", dmsID)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "central key generation is not enabled for this DMS (RFC 9483 §4.1.6)",
			FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
		})
		return
	}

	// Central key generation needs a signature-protected request: the protection
	// signer certificate is the CMS recipient and carries the key usage that
	// selects (and authorises) the key-management technique.
	recipient := signerCert
	if recipient == nil {
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "central key generation requires a signature-protected request (RFC 9483 §4.1.6)",
			FailInfoBit: corecmp.PKIFailureInfoBadRequest,
		})
		return
	}

	technique, err := kga.TechniqueFor(recipient.PublicKey)
	if err != nil {
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      fmt.Sprintf("central key generation: %v", err),
			FailInfoBit: corecmp.PKIFailureInfoBadCertTemplate,
		})
		return
	}
	// RFC011: the DMS may restrict which CKG recipient mechanisms it will use
	// (CentralKeyGeneration.AllowedRecipientMethods, per operation). The
	// mechanism is derived from the recipient key type (RSA→KTRI, EC→KARI); if
	// that mechanism is not on the allow-list, the request is notAuthorized.
	if !ckgRecipientMethodAllowed(enrollOpts, requestTag, technique) {
		lFunc.Warnf("kga: recipient mechanism %s not permitted by DMS CKG allow-list", technique)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      fmt.Sprintf("central key generation recipient mechanism %s is not permitted by this DMS", technique),
			FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
		})
		return
	}
	// RFC 9483 §4.1.6.1/§4.1.6.2: the recipient certificate MUST allow the chosen
	// technique — keyEncipherment for KTRI, keyAgreement for KARI. Missing it is
	// notAuthorized.
	if rej := validateKGARecipientKeyUsage(req.CertReqID, technique, recipient); rej != nil {
		lFunc.Warnf("kga: recipient cert key usage rejects %s: %s", technique, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	keyGen, ok := r.svc.(services.LightweightCMPKeyGenerator)
	if !ok {
		lFunc.Errorf("kga: service does not implement LightweightCMPKeyGenerator")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "central key generation not supported", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	issuanceCtx := context.WithoutCancel(ctx.Request.Context())
	sw := software.NewSoftwareCryptoEngine(lFunc)

	// 1. Generate the end-entity key pair the server will hand back.
	generated, err := generateKGAKey(issuanceCtx, sw, req.KGAKeyAlgorithm)
	if err != nil {
		lFunc.Errorf("kga: generate end-entity key: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "could not generate key", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	// 2. Issue a certificate for the generated public key via the normal
	// enrollment path (a synthetic CSR carrying the requested subject/extensions).
	spkiDER, err := x509.MarshalPKIXPublicKey(generated.Public())
	if err != nil {
		lFunc.Errorf("kga: marshal generated public key: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "internal error", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	csr, err := corecmp.BuildSyntheticCSR(req.SubjectDER, spkiDER, req.Extensions)
	if err != nil {
		lFunc.Errorf("kga: build synthetic CSR: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build CSR", dmsID, corecmp.PKIFailureInfoBadCertTemplate)
		return
	}
	cert, err := enroll(issuanceCtx, csr, recipient)
	if err != nil {
		lFunc.Errorf("kga: issue certificate: %v", err)
		failBit := corecmp.PKIFailureInfoSystemFailure
		if errors.Is(err, errs.ErrDMSEnrollInvalidCert) {
			failBit = corecmp.PKIFailureInfoSignerNotTrusted
		}
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), err.Error(), dmsID, failBit)
		return
	}

	// 3. Ephemeral KGA signer (id-kp-cmKGA) that signs the CMS SignedData.
	signerKey, kgaCert, kgaChain, err := mintHelperCert(issuanceCtx, lFunc, keyGen, dmsID, "Lamassu CMP KGA Signer", services.KGAHelperSigner)
	if err != nil {
		lFunc.Errorf("kga: issue KGA signer certificate: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "could not issue KGA signer certificate", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	buildIn := kga.BuildInput{
		GeneratedKey:  generated,
		RecipientCert: recipient,
		KGACert:       kgaCert,
		KGAChain:      kgaChain,
		KGASigner:     signerKey,
	}

	// extraCerts[0] MUST be the certificate the validator matches CMS identifiers
	// against (for KARI the ECDH originator; for KTRI the EE recipient). The
	// OUTER PKIMessage protection, though, is signed by the DMS's normal
	// protection credentials whenever configured — for BOTH techniques — so the
	// response's sender identity keeps matching what the client pinned (openssl
	// cmp -srvcert / -expect_sender). Signing party and CMS originator are
	// independent: a KARI recipient derives the CEK from the originator in
	// extraCerts regardless of who signed the message. (An earlier revision
	// signed KARI responses with the originator itself, which made a
	// -srvcert-pinning client reject them as "unexpected sender: /CN=Lamassu
	// CMP ECDH Originator".) fallbackCert/Signer are used only when the DMS has
	// no protection credentials configured at all.
	var extraCerts []*x509.Certificate
	var fallbackCert *x509.Certificate
	var fallbackSigner crypto.Signer

	if technique == kga.TechniqueKARI {
		// 4. Ephemeral EC originator: the ECDH peer, kept at extraCerts[0].
		origKey, origCert, origChain, err := mintHelperCert(issuanceCtx, lFunc, keyGen, dmsID, "Lamassu CMP KARI Originator", services.KGAHelperKARIOriginator)
		if err != nil {
			lFunc.Errorf("kga: issue KARI originator certificate: %v", err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "could not issue KARI originator certificate", dmsID, corecmp.PKIFailureInfoSystemFailure)
			return
		}
		buildIn.KARIOriginatorKey = origKey
		buildIn.KARIOriginatorCert = origCert

		extraCerts = append(extraCerts, origCert)
		extraCerts = append(extraCerts, origChain...)
		extraCerts = append(extraCerts, kgaCert)
		extraCerts = append(extraCerts, kgaChain...)
		// If no DMS creds are configured, sign with the originator so it stays
		// both findable (extraCerts[0]) and the verifiable signer.
		fallbackCert = origCert
		fallbackSigner = origKey
	} else {
		// KTRI: the EE recipient cert must be extraCerts[0].
		extraCerts = append(extraCerts, recipient)
		extraCerts = append(extraCerts, kgaCert)
		extraCerts = append(extraCerts, kgaChain...)
		fallbackCert = kgaCert
		fallbackSigner = signerKey
	}

	var protectionSignerCert *x509.Certificate
	var protectionSigner crypto.Signer
	if provider, ok := r.svc.(services.LightweightCMPProtectionProvider); ok {
		if dmsChain, dmsSigner, credErr := provider.LWCProtectionCredentials(issuanceCtx, dmsID); credErr == nil && len(dmsChain) > 0 && dmsSigner != nil {
			protectionSignerCert = dmsChain[0]
			protectionSigner = dmsSigner
			// Append the DMS chain so -trusted-only clients can still build the
			// protection path; the originator/recipient stays at extraCerts[0].
			extraCerts = append(extraCerts, dmsChain...)
		}
	}
	if protectionSignerCert == nil {
		protectionSignerCert = fallbackCert
		protectionSigner = fallbackSigner
	}

	// 5. Build the EnvelopedData(SignedData(AsymmetricKeyPackage)).
	envelopedDataDER, err := kga.BuildKeyPackage(buildIn)
	if err != nil {
		lFunc.Errorf("kga: build key package: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "could not build key package", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	// 6. Assemble the ip/cp/kup body carrying the issued cert + enveloped key.
	bodyDER, err := corecmp.MarshalKGACertRepBody(req.CertReqID, int(corecmp.PKIStatus(0)), cert.Raw, envelopedDataDER)
	if err != nil {
		lFunc.Errorf("kga: marshal cert rep body: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build response", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	// 7. Sign and send. The request carried pvno=3, which buildResponseHeader
	// echoes, satisfying the §4.1.6 requirement that the response be cmp2021(3).
	respDER, err := marshalProtectedResponseWithSigner(header, respTag, bodyDER, extraCerts, protectionSignerCert, protectionSigner)
	if err != nil {
		lFunc.Errorf("kga: marshal protected response: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build response", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	lFunc.Infof("kga: issued cert SN=%s and delivered %s-wrapped generated key (CN=%s)",
		hex.EncodeToString(cert.SerialNumber.Bytes()), technique, csr.Subject.CommonName)
	ctx.Data(http.StatusOK, "application/pkixcmp", respDER)
}

// validateKGARecipientKeyUsage checks that the recipient (request protection)
// certificate carries the KeyUsage required by the selected KGA technique.
// Returns a notAuthorized rejection when it does not (RFC 9483 §4.1.6).
func validateKGARecipientKeyUsage(certReqID int, technique kga.Technique, recipient *x509.Certificate) *corecmp.CertRequestRejection {
	switch technique {
	case kga.TechniqueKTRI:
		if recipient.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			return &corecmp.CertRequestRejection{
				CertReqID:   certReqID,
				Reason:      "recipient certificate lacks the keyEncipherment KeyUsage required for key transport (RFC 9483 §4.1.6.1)",
				FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
			}
		}
	case kga.TechniqueKARI:
		if recipient.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return &corecmp.CertRequestRejection{
				CertReqID:   certReqID,
				Reason:      "recipient certificate lacks the keyAgreement KeyUsage required for key agreement (RFC 9483 §4.1.6.2)",
				FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
			}
		}
	}
	return nil
}

// generateKGAKey generates the end-entity key pair to be delivered, choosing the
// algorithm from the CertTemplate hint (RSA or ECDSA). When the request omitted
// the publicKey field entirely (no hint), it defaults to RSA-2048.
func generateKGAKey(ctx context.Context, sw *software.SoftwareCryptoEngine, alg x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	switch alg {
	case x509.ECDSA:
		_, key, err := sw.CreateECDSAPrivateKey(ctx, elliptic.P256())
		return key, err
	case x509.RSA, x509.UnknownPublicKeyAlgorithm:
		_, key, err := sw.CreateRSAPrivateKey(ctx, 2048)
		return key, err
	default:
		return nil, fmt.Errorf("unsupported key algorithm hint %v", alg)
	}
}

// selfSignedCSR builds and parses a PKCS#10 CSR for cn signed by key. Used for
// the ephemeral KGA helper certificates, whose keys the controller owns.
func selfSignedCSR(cn string, key crypto.Signer) (*x509.CertificateRequest, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// deferForApproval implements the phased-workflow enrollment path: it persists
// the request as a PENDING transaction (storing the synthesized CSR so the
// approval step can issue later) and returns a CMP "waiting" response. The EE
// then polls with pollReq until an administrator approves the transaction and
// the cert becomes available.
func (r *cmpHttpRoutes) deferForApproval(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header *corecmp.RequestPKIHeader,
	req *corecmp.CertRequest,
	csr *x509.CertificateRequest,
	dmsID string,
	enrollOpts *models.EnrollmentOptionsLWCRFC9483,
	params issueParams,
	txHex string,
) {
	// The waiting response carries no certificate, so it must not advertise
	// implicit confirmation; that is negotiated when the cert is finally
	// delivered via pollReq.
	header.ResponseImplicitConfirm = false

	storeCtx := context.WithoutCancel(ctx.Request.Context())
	if storeErr := r.store.Insert(storeCtx, models.CMPTransaction{
		TransactionID:     txHex,
		DMSID:             dmsID,
		State:             models.CMPTransactionStatePending,
		CSR:               (*models.X509CertificateRequest)(csr),
		IsReenrollment:    params.isReenrollment,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		WFXJobID:          params.wfxJobID,
		ReceivedNonce:     hex.EncodeToString(header.SenderNonce),
		// kur only: hex serial of the certificate being updated, so the
		// pending-update lock (RFC 9483 §4.1.3) applies to phased key-updates
		// exactly as it does to direct ones.
		SupersededCertSerial: params.supersededCertSerial,
		RegToken:             req.RegToken,
		// Approval is a human action: give it a generous window so the request
		// isn't swept before an operator can act on it (RFC 4210 §5.3.22 leaves
		// the polling/approval window to server policy). Per-DMS via
		// EnrollmentOptionsLWCRFC9483.ApprovalTimeout; cmpApprovalTTL is the
		// fallback when the DMS leaves it at zero.
		ExpiresAt: time.Now().Add(approvalTimeoutOrDefault(enrollOpts.ApprovalTimeout)),
		CreatedAt: time.Now(),
	}); storeErr != nil {
		if errors.Is(storeErr, errs.ErrCMPTransactionAlreadyExists) {
			lFunc.Warnf("duplicate transactionID %s", txHex)
			r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "transactionID already in use", dmsID, corecmp.PKIFailureInfoTransactionIDInUse)
			return
		}
		lFunc.Errorf("store PENDING transaction: %v", storeErr)
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "internal error", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	waitingDER, err := corecmp.MarshalCertRepWaitingBody(req.CertReqID)
	if err != nil {
		lFunc.Errorf("build waiting cert rep body: %v", err)
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "cannot build response", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	responseDER := r.sendRawBody(ctx, lFunc, *header, params.respTag, waitingDER, dmsID)
	if len(responseDER) == 0 {
		return
	}
	lFunc.Infof("phased workflow: tx %s parked awaiting admin approval, returned waiting response", txHex)
	r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     txHex,
		DMSID:             dmsID,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		State:             cmpwfx.CMPStateAwaitingApproval,
		Metadata: withCMPMessageB64(map[string]any{
			"certReqId":      req.CertReqID,
			"isReenrollment": params.isReenrollment,
			"responseType":   cmpTagToString(params.respTag),
		}, cmpMetadataResponseB64, responseDER),
	})
}
