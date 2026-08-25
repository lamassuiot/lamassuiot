package cmp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"time"
)

// cmpMaxMessageTimeSkew is the absolute drift tolerated between the EE's
// declared messageTime and the server's wall clock, per RFC 9483 §3.5
// (failInfo badTime). Five minutes mirrors the typical Kerberos / TLS clock-
// skew envelope and is well above NTP error margins while still preventing
// replays of stale captured messages.
const cmpMaxMessageTimeSkew = 5 * time.Minute

// cmpEnvelopeRejection is what validateRequestEnvelope returns when the
// incoming message violates a wire-level invariant. The controller maps it to
// a PKIMessage error response carrying the right failInfo bit.
type cmpEnvelopeRejection struct {
	reason   string
	failInfo int
}

func (e *cmpEnvelopeRejection) Error() string { return e.reason }

// validateRequestEnvelope enforces the wire-level invariants every CMP
// message MUST satisfy before any application logic runs. It groups the
// checks that previously lived inline in HandleCMP so the dispatcher stays a
// dispatcher and the validation rules can be unit-tested in isolation
// (audit findings R1, R2, A1).
//
// Checks performed, in order:
//
//   - pvno ∈ {cmp2000, cmp2021}                      → unsupportedVersion
//   - transactionID present and ≥128 bits             → badDataFormat
//   - senderNonce present and ≥128 bits               → badSenderNonce
//   - messageTime present and within cmpMaxMessageTimeSkew → badTime
//     (RFC 9483 §3.1 line 725 requires messageTime on every signature-
//     protected message; RFC 9483 §3.5 gives badTime for both "absent when
//     required" and "outside the freshness window")
//
// The sender-vs-subject check is intentionally NOT performed here because
// the protection cert is not known until verifyRequestProtection has run.
// See verifySenderMatchesProtectionCert for that pairing.
func validateRequestEnvelope(h corecmp.RequestPKIHeader, now time.Time, bodyTag int) *cmpEnvelopeRejection {
	if h.PVNO != corecmp.PVNOCMP2000 && h.PVNO != corecmp.PVNOCMP2021 {
		return &cmpEnvelopeRejection{
			reason:   fmt.Sprintf("unsupported protocol version %d (must be cmp2000(2) or cmp2021(3))", h.PVNO),
			failInfo: corecmp.PKIFailureInfoUnsupportedVersion,
		}
	}
	if len(h.TransactionID) == 0 {
		// A certConf that carries no transactionID cannot be correlated to any
		// open transaction; RFC 9483 §4.1.1 treats this as a badRequest (the
		// confirmation references a non-existent exchange) rather than the
		// malformed-field semantics of badDataFormat used for the issuance
		// request bodies.
		failInfo := corecmp.PKIFailureInfoBadDataFormat
		if bodyTag == corecmp.BodyTagCertConf {
			failInfo = corecmp.PKIFailureInfoBadRequest
		}
		return &cmpEnvelopeRejection{
			reason:   "transactionID is required (RFC 9483 §3.5)",
			failInfo: failInfo,
		}
	}
	if len(h.TransactionID) < 16 {
		return &cmpEnvelopeRejection{
			reason:   "transactionID must contain at least 128 bits of data (RFC 9483 §3.1)",
			failInfo: corecmp.PKIFailureInfoBadDataFormat,
		}
	}
	if len(h.SenderNonce) < 16 {
		return &cmpEnvelopeRejection{
			reason:   "senderNonce must be present and contain at least 128 bits (RFC 9483 §3.5)",
			failInfo: corecmp.PKIFailureInfoBadSenderNonce,
		}
	}
	if h.MessageTime.IsZero() {
		return &cmpEnvelopeRejection{
			reason:   "messageTime is required (RFC 9483 §3.1)",
			failInfo: corecmp.PKIFailureInfoBadTime,
		}
	}
	drift := now.Sub(h.MessageTime)
	if drift < 0 {
		drift = -drift
	}
	if drift > cmpMaxMessageTimeSkew {
		return &cmpEnvelopeRejection{
			reason: fmt.Sprintf("messageTime drift %s exceeds %s (RFC 9483 §3.5)",
				drift.Round(time.Second), cmpMaxMessageTimeSkew),
			failInfo: corecmp.PKIFailureInfoBadTime,
		}
	}
	return nil
}

// oidConfirmWaitTime is id-it-confirmWaitTime (1.3.6.1.5.5.7.4.14).
var oidConfirmWaitTime = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 14}

// validateGeneralInfo enforces the RFC 9483 §3.1 rules on the PKIHeader
// generalInfo entries that are meaningful regardless of body type:
//
//   - id-it-implicitConfirm's value, when the OID is present, MUST be NULL.
//   - id-it-confirmWaitTime's value, when the OID is present, MUST be
//     GeneralizedTime (not UTCTime or any other type).
//   - the two are mutually exclusive — a response cannot both promise
//     immediate implicit confirmation and tell the EE how long to wait for one.
func validateGeneralInfo(generalInfo []asn1.RawValue) *cmpEnvelopeRejection {
	var hasImplicitConfirm, hasConfirmWaitTime bool
	var implicitConfirmValue, confirmWaitTimeValue asn1.RawValue

	for _, item := range generalInfo {
		var itav struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(item.FullBytes, &itav); err != nil {
			continue
		}
		switch {
		case itav.OID.Equal(corecmp.OIDImplicitConfirm()):
			hasImplicitConfirm = true
			implicitConfirmValue = itav.Value
		case itav.OID.Equal(oidConfirmWaitTime):
			hasConfirmWaitTime = true
			confirmWaitTimeValue = itav.Value
		}
	}

	if hasImplicitConfirm && hasConfirmWaitTime {
		return &cmpEnvelopeRejection{
			reason:   "implicitConfirm and confirmWaitTime are mutually exclusive in generalInfo (RFC 9483 §3.1)",
			failInfo: corecmp.PKIFailureInfoBadRequest,
		}
	}
	// infoValue is OPTIONAL at the InfoTypeAndValue level (RFC 4210), and some
	// clients omit it entirely rather than spell out NULL explicitly — both
	// are valid for implicitConfirm. Only a PRESENT, non-NULL value (the
	// negative case RFC 9483 §3.1 forbids) is rejected.
	implicitConfirmPresent := len(implicitConfirmValue.FullBytes) > 0
	if hasImplicitConfirm && implicitConfirmPresent &&
		!(implicitConfirmValue.Class == asn1.ClassUniversal && implicitConfirmValue.Tag == asn1.TagNull) {
		return &cmpEnvelopeRejection{
			reason:   "implicitConfirm value must be NULL (RFC 9483 §3.1)",
			failInfo: corecmp.PKIFailureInfoBadRequest,
		}
	}
	if hasConfirmWaitTime && !(confirmWaitTimeValue.Class == asn1.ClassUniversal && confirmWaitTimeValue.Tag == asn1.TagGeneralizedTime) {
		return &cmpEnvelopeRejection{
			reason:   "confirmWaitTime value must be GeneralizedTime (RFC 9483 §3.1)",
			failInfo: corecmp.PKIFailureInfoBadDataFormat,
		}
	}
	return nil
}

// verifySenderMatchesProtectionCert enforces RFC 9483 §3.5: when signature-
// based protection is used, the PKIHeader sender field MUST match the
// subject of the CMP protection certificate. Returns nil when the rule is
// satisfied, or a cmpEnvelopeRejection (failInfo badMessageCheck) otherwise.
//
// The CMP sender is a GeneralName CHOICE; only the directoryName ([4])
// alternative is meaningful for this check. Any other CHOICE (rfc822Name,
// dNSName, …) is incompatible with the protection cert's Subject and is
// rejected.
func verifySenderMatchesProtectionCert(senderRaw asn1.RawValue, eeCert *x509.Certificate) *cmpEnvelopeRejection {
	if eeCert == nil {
		// No protection cert (unprotected message accepted upstream); no
		// constraint to apply.
		return nil
	}

	// The sender RawValue carries the GeneralName CHOICE encoded as a context-
	// specific [4] tag wrapping an RDNSequence. NULL-DN (zero-length RDN
	// sequence) is the historical fallback when a sender is "anonymous"; with
	// signature-based protection the EE has a real identity and MUST use it.
	if senderRaw.Class != asn1.ClassContextSpecific || senderRaw.Tag != 4 {
		return &cmpEnvelopeRejection{
			reason:   fmt.Sprintf("sender field must be a directoryName GeneralName (got class=%d tag=%d)", senderRaw.Class, senderRaw.Tag),
			failInfo: corecmp.PKIFailureInfoBadMessageCheck,
		}
	}

	var senderRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(senderRaw.Bytes, &senderRDN); err != nil {
		return &cmpEnvelopeRejection{
			reason:   fmt.Sprintf("sender field RDNSequence: %v", err),
			failInfo: corecmp.PKIFailureInfoBadMessageCheck,
		}
	}

	subjectRDN := eeCert.Subject.ToRDNSequence()
	if !rdnSequencesEqual(senderRDN, subjectRDN) {
		return &cmpEnvelopeRejection{
			reason: fmt.Sprintf("sender DN does not match protection certificate subject (sender=%q, cert subject=%q) (RFC 9483 §3.5)",
				senderRDN.String(), eeCert.Subject.String()),
			failInfo: corecmp.PKIFailureInfoBadMessageCheck,
		}
	}
	return nil
}

// verifySenderKIDMatchesProtectionCert enforces RFC 9483 §3.1: a signature-
// protected PKIMessage MUST carry a senderKID equal to the SubjectKeyIdentifier
// of the CMP protection certificate. Returns nil when satisfied, or a
// cmpEnvelopeRejection (failInfo badMessageCheck) otherwise.
//
// eeCert nil means the message was unprotected (accepted upstream) — no rule to
// apply. When the protection cert carries no SubjectKeyIdentifier we cannot
// enforce the byte match; we still require senderKID to be present (the RFC
// makes it mandatory) but skip the equality check in that edge case.
func verifySenderKIDMatchesProtectionCert(senderKID []byte, eeCert *x509.Certificate) *cmpEnvelopeRejection {
	if eeCert == nil {
		return nil
	}
	if len(senderKID) == 0 {
		return &cmpEnvelopeRejection{
			reason:   "senderKID is required for signature-based protection (RFC 9483 §3.1)",
			failInfo: corecmp.PKIFailureInfoBadMessageCheck,
		}
	}
	if len(eeCert.SubjectKeyId) == 0 {
		return nil
	}
	if !bytes.Equal(senderKID, eeCert.SubjectKeyId) {
		return &cmpEnvelopeRejection{
			reason:   "senderKID does not match the protection certificate's SubjectKeyIdentifier (RFC 9483 §3.1)",
			failInfo: corecmp.PKIFailureInfoBadMessageCheck,
		}
	}
	return nil
}

// rdnSequencesEqual compares two RDN sequences by canonical DER encoding so
// any ordering / encoding nuance produced by either side resolves to a single
// byte string. This avoids the gotchas of comparing pkix.Name.String()
// (locale-dependent attribute names) or hand-walking the sequence.
func rdnSequencesEqual(a, b pkix.RDNSequence) bool {
	aDER, err := asn1.Marshal(a)
	if err != nil {
		return false
	}
	bDER, err := asn1.Marshal(b)
	if err != nil {
		return false
	}
	if len(aDER) != len(bDER) {
		return false
	}
	for i := range aDER {
		if aDER[i] != bDER[i] {
			return false
		}
	}
	return true
}
