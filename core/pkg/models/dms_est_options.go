package models

type EnrollmentOptionsESTRFC7030 struct {
	AuthMode                   ESTAuthMode                  `json:"auth_mode"`
	AuthOptionsMTLS            AuthOptionsClientCertificate `json:"client_certificate_settings"`
	AuthOptionsExternalWebhook WebhookCall                  `json:"external_webhook"`
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
