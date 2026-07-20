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

type EnrollmentOptionsESTRFC7030 struct {
	AuthMode                   ESTAuthMode                  `json:"auth_mode"`
	AuthOptionsMTLS            AuthOptionsClientCertificate `json:"client_certificate_settings"`
	AuthOptionsExternalWebhook WebhookCall                  `json:"external_webhook_settings"`
}

// AuthSettings returns the shared authentication policy for this EST DMS.
func (o EnrollmentOptionsESTRFC7030) AuthSettings() EnrollmentAuthSettings {
	return EnrollmentAuthSettings{
		AuthMode:                   EnrollmentAuthMode(o.AuthMode),
		AuthOptionsMTLS:            o.AuthOptionsMTLS,
		AuthOptionsExternalWebhook: o.AuthOptionsExternalWebhook,
	}
}

type ReEnrollmentSettings struct {
	ReEnrollmentOptionsESTRFC7030 EnrollmentOptionsESTRFC7030 `json:"est_rfc7030_settings"`
	AdditionalValidationCAs       []string                    `json:"additional_validation_cas"`
	RevokeOnReEnrollment          bool                        `json:"revoke_on_reenrollment"`
	ReEnrollmentDelta             TimeDuration                `json:"reenrollment_delta"`
	EnableExpiredRenewal          bool                        `json:"enable_expired_renewal"`
	PreventiveReEnrollmentDelta   TimeDuration                `json:"preventive_delta"` // (expiration time - delta < time.now) at witch point an event is issued notify its time to reenroll
	CriticalReEnrollmentDelta     TimeDuration                `json:"critical_delta"`   // (expiration time - delta < time.now) at witch point an event is issued notify critical status
}

type CADistributionSettings struct {
	IncludeLamassuSystemCA bool     `json:"include_system_ca"`
	IncludeEnrollmentCA    bool     `json:"include_enrollment_ca"`
	ManagedCAs             []string `json:"managed_cas"`
}
