package models

// EnrollmentOptionsLWCRFC9483 holds CMP-specific enrollment settings as defined
// by RFC 9483 (Lightweight CMP Profile) and RFC 4210.
type EnrollmentOptionsLWCRFC9483 struct {
	// AcceptImplicit controls whether the server is willing to skip the
	// certConf round-trip when the EE asks for implicit confirmation
	// (id-it-implicitConfirm OID in the request's generalInfo).
	//
	// When true and the EE requested it, the server omits the certConf step
	// and includes id-it-implicitConfirm in the response generalInfo.
	// When false, the server always requires explicit certConf even if the
	// EE asked for implicit (the OID is dropped silently).
	//
	// RFC 9483 §4.1.1 / RFC 4210 §5.2.8.
	AcceptImplicit bool `json:"accept_implicit"`

	// ConfirmationTimeout is the maximum duration the server waits for a
	// certConf message when explicit confirmation is required.
	// RFC 4210 §5.2.8.
	ConfirmationTimeout TimeDuration `json:"confirmation_timeout"`

	// AuthMode selects how the RA authenticates the end-entity's CMP request.
	// Currently only CLIENT_CERTIFICATE (mTLS / signature-based protection) is supported.
	AuthMode CMPAuthMode `json:"auth_mode"`

	// AuthOptionsMTLS holds the parameters used when AuthMode is CLIENT_CERTIFICATE.
	// Reuses the same structure as the EST mTLS auth option.
	AuthOptionsMTLS AuthOptionsClientCertificate `json:"client_certificate_settings"`

	// ProtectionCertificateSerialNumber is the serial number of the end-entity certificate
	// whose key the RA uses to sign CMP response messages (signature-based PKIMessage protection).
	// The key associated with the certificate must be stored in the KMS.
	ProtectionCertificateSerialNumber string `json:"protection_certificate"`

	// EnforceRequestProtection controls whether incoming CMP requests MUST carry
	// signature-based protection. When true, requests without a Protection field
	// are rejected with a CMP error. When false (default), unprotected requests
	// are accepted (e.g. for testing or clients that do not support request signing).
	EnforceRequestProtection bool `json:"enforce_request_protection"`

	// EnforcePOPO controls whether the Proof-Of-Possession (POPO) signature inside
	// the CRMF CertReqMsg MUST be verified. RFC 9483 §4.1 requires POPO for ir/cr
	// unless the request is protected by an authorized RA (raVerified) or possession
	// is proven out-of-band (e.g. mTLS provides proof-of-identity+possession at the
	// transport layer). For KUR, the message-level protection IS the POPO per
	// RFC 9483 §4.1.3; when EnforcePOPO is true an unprotected KUR is rejected.
	// Set to false when mTLS or another transport-level mechanism already proves
	// possession so the inner CRMF self-signature is redundant.
	// Defaults to false (Go zero value); set to true to enforce verification.
	EnforcePOPO bool `json:"enforce_popo"`
}

type CMPAuthMode string

const (
	CMPAuthModeClientCertificate CMPAuthMode = "CLIENT_CERTIFICATE"
)
