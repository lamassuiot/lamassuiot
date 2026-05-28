package models

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
	AuthMode                   EnrollmentAuthMode           `json:"auth_mode"`
	AuthOptionsMTLS            AuthOptionsClientCertificate `json:"client_certificate_settings"`
	AuthOptionsExternalWebhook WebhookCall                  `json:"external_webhook"`
}

// AuthSettings returns the shared authentication policy for this EST DMS.
func (o EnrollmentOptionsESTRFC7030) AuthSettings() EnrollmentAuthSettings {
	return EnrollmentAuthSettings{
		AuthMode:                   o.AuthMode,
		AuthOptionsMTLS:            o.AuthOptionsMTLS,
		AuthOptionsExternalWebhook: o.AuthOptionsExternalWebhook,
	}
}

type ReEnrollmentSettings struct {
	AdditionalValidationCAs     []string     `json:"additional_validation_cas"`
	RevokeOnReEnrollment        bool         `json:"revoke_on_reenrollment"`
	ReEnrollmentDelta           TimeDuration `json:"reenrollment_delta"`
	EnableExpiredRenewal        bool         `json:"enable_expired_renewal"`
	PreventiveReEnrollmentDelta TimeDuration `json:"preventive_delta"` // (expiration time - delta < time.now) at witch point an event is issued notify its time to reenroll
	CriticalReEnrollmentDelta   TimeDuration `json:"critical_delta"`   // (expiration time - delta < time.now) at witch point an event is issued notify critical status
}

type CADistributionSettings struct {
	IncludeLamassuSystemCA bool     `json:"include_system_ca"`
	IncludeEnrollmentCA    bool     `json:"include_enrollment_ca"`
	ManagedCAs             []string `json:"managed_cas"`
}
