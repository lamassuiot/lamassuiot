package models

// EnrollmentAuthMode is the protocol-agnostic currency that EnrollmentAuthSettings
// normalizes EST's ESTAuthMode and CMP's CMPAuthMode into, so authenticateEnrollment
// can run a single switch shared by both protocols. It is not exposed on either
// protocol's own DTO — EST and CMP each keep their own named type/constants.
type EnrollmentAuthMode string

const (
	EnrollmentAuthModeClientCertificate           EnrollmentAuthMode = "CLIENT_CERTIFICATE"
	EnrollmentAuthModeExternalWebhook             EnrollmentAuthMode = "EXTERNAL_WEBHOOK"
	EnrollmentAuthModeClientCertificateAndWebhook EnrollmentAuthMode = "CLIENT_CERTIFICATE_AND_EXTERNAL_WEBHOOK"
	EnrollmentAuthModeNoAuth                      EnrollmentAuthMode = "NO_AUTH"
)

// EnrollmentAuthSettings is the protocol-agnostic authentication policy shared
// by EST and CMP enrollment. The auth *mechanism* differs by protocol (EST
// presents an mTLS client certificate; CMP presents the signature-based
// message-protection signer certificate), but the policy — which mode, which
// ValidationCAs, which webhook — is identical, so both protocols expose it via
// AuthSettings() and run the same authenticator.
type EnrollmentAuthSettings struct {
	AuthMode                   EnrollmentAuthMode
	AuthOptionsMTLS            AuthOptionsClientCertificate
	AuthOptionsExternalWebhook WebhookCall
}

// ESTSettings is the complete configuration of a DMS that enrolls over EST
// (RFC 7030). It is reachable only via DMSSettings.EST, which is non-nil
// exactly when DMSSettings.Protocol is EST.
type ESTSettings struct {
	ServerKeyGen           ServerKeyGenSettings    `json:"server_keygen_settings"`
	EnrollmentSettings     ESTEnrollmentSettings   `json:"enrollment_settings"`
	ReEnrollmentSettings   ESTReEnrollmentSettings `json:"reenrollment_settings"`
	CADistributionSettings CADistributionSettings  `json:"ca_distribution_settings"`
	IssuanceProfileID      string                  `json:"issuance_profile_id"`
	IssuanceProfile        *IssuanceProfile        `json:"issuance_profile"`
}

// ESTEnrollmentSettings carries the EST authentication policy plus the shared
// enrollment knobs. The auth fields sit directly on this struct — the enclosing
// ESTSettings already says "EST", so a nested est_rfc7030_settings wrapper
// would only repeat it.
type ESTEnrollmentSettings struct {
	AuthMode                   ESTAuthMode                  `json:"auth_mode"`
	AuthOptionsMTLS            AuthOptionsClientCertificate `json:"client_certificate_settings"`
	AuthOptionsExternalWebhook WebhookCall                  `json:"external_webhook_settings"`

	CommonEnrollmentSettings
}

// AuthSettings returns the shared authentication policy for this EST DMS.
func (o ESTEnrollmentSettings) AuthSettings() EnrollmentAuthSettings {
	return EnrollmentAuthSettings{
		AuthMode:                   EnrollmentAuthMode(o.AuthMode),
		AuthOptionsMTLS:            o.AuthOptionsMTLS,
		AuthOptionsExternalWebhook: o.AuthOptionsExternalWebhook,
	}
}

// ESTReEnrollmentSettings mirrors ESTEnrollmentSettings for re-enrollment: EST
// re-enrollment authenticates independently of enrollment (typically against
// the current device certificate), so it carries its own auth policy.
type ESTReEnrollmentSettings struct {
	AuthMode                   ESTAuthMode                  `json:"auth_mode"`
	AuthOptionsMTLS            AuthOptionsClientCertificate `json:"client_certificate_settings"`
	AuthOptionsExternalWebhook WebhookCall                  `json:"external_webhook_settings"`

	CommonReEnrollmentSettings
}

// AuthSettings returns the shared authentication policy for EST re-enrollment.
func (o ESTReEnrollmentSettings) AuthSettings() EnrollmentAuthSettings {
	return EnrollmentAuthSettings{
		AuthMode:                   EnrollmentAuthMode(o.AuthMode),
		AuthOptionsMTLS:            o.AuthOptionsMTLS,
		AuthOptionsExternalWebhook: o.AuthOptionsExternalWebhook,
	}
}

type CADistributionSettings struct {
	IncludeLamassuSystemCA bool     `json:"include_system_ca"`
	IncludeEnrollmentCA    bool     `json:"include_enrollment_ca"`
	ManagedCAs             []string `json:"managed_cas"`
}
