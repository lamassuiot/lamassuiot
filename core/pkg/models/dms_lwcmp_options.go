package models

// EnrollmentOptionsLWCRFC9483 holds CMP-specific enrollment settings as defined
// by RFC 9483 (Lightweight CMP Profile) and RFC 4210.
type EnrollmentOptionsLWCRFC9483 struct {
	// ConfirmationMode controls whether the EE must send an explicit certConf
	// message (EXPLICIT) or whether confirmation is implied (IMPLICIT).
	// RFC 9483 §4.1.1 / RFC 4210 §5.2.8.
	ConfirmationMode CMPConfirmationMode `json:"confirmation_mode"`

	// ConfirmationTimeout is the maximum duration the server waits for a
	// certConf message when ConfirmationMode is EXPLICIT.
	// RFC 4210 §5.2.8.
	ConfirmationTimeout TimeDuration `json:"confirmation_timeout"`

	// EnrollmentCA is the ID of the CA used to sign certificates issued via
	// this CMP profile. Overrides EnrollmentSettings.EnrollmentCA when set.
	EnrollmentCA string `json:"enrollment_ca"`

	// AuthMode selects how the RA authenticates the end-entity's CMP request.
	// Currently only CLIENT_CERTIFICATE (mTLS / signature-based protection) is supported.
	AuthMode CMPAuthMode `json:"auth_mode"`

	// AuthOptionsMTLS holds the parameters used when AuthMode is CLIENT_CERTIFICATE.
	// Reuses the same structure as the EST mTLS auth option.
	AuthOptionsMTLS AuthOptionsClientCertificate `json:"client_certificate_settings"`

	// ProtectionCA is the ID of the CA whose key the RA uses to sign CMP
	// response messages (signature-based PKIMessage protection).
	// The CA certificate is sent as the protection certificate in the response.
	// If empty, CMP responses are sent unprotected.
	ProtectionCA string `json:"protection_ca"`
}

type CMPConfirmationMode string

const (
	CMPConfirmationModeImplicit CMPConfirmationMode = "IMPLICIT"
	CMPConfirmationModeExplicit CMPConfirmationMode = "EXPLICIT"
)

type CMPAuthMode string

const (
	CMPAuthModeClientCertificate CMPAuthMode = "CLIENT_CERTIFICATE"
)
