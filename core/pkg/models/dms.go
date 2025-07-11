package models

import (
	"time"
)

type DMSStatus string

const (
	PendingACKDMSStatus DMSStatus = "PENDING_ACK"
	ActiveDMSStatus     DMSStatus = "ACTIVE"
	RevokedDMSStatus    DMSStatus = "REVOKED"
	ExpiredDMSStatus    DMSStatus = "EXPIRED"
)

type DMS struct {
	ID           string         `json:"id" gorm:"primaryKey"`
	Name         string         `json:"name"`
	Metadata     map[string]any `json:"metadata" gorm:"serializer:json"`
	CreationDate time.Time      `json:"creation_ts"`
	Settings     DMSSettings    `json:"settings" gorm:"serializer:json"`
}

type DMSSettings struct {
	ServerKeyGen           ServerKeyGenSettings   `json:"server_keygen_settings"`
	EnrollmentSettings     EnrollmentSettings     `json:"enrollment_settings"`
	ReEnrollmentSettings   ReEnrollmentSettings   `json:"reenrollment_settings"`
	CADistributionSettings CADistributionSettings `json:"ca_distribution_settings"`
	IssuanceProfile        *IssuanceProfile       `json:"issuance_profile"`
}

type EnrollmentProto string

const (
	EST EnrollmentProto = "EST_RFC7030"
)

type ServerKeyGenSettings struct {
	Enabled bool            `json:"enabled"`
	Key     ServerKeyGenKey `json:"key"`
}

type ServerKeyGenKey struct {
	Type KeyType `json:"type"`
	Bits int     `json:"bits"`
}

type DeviceProvisionProfile struct {
	Icon      string         `json:"icon"`
	IconColor string         `json:"icon_color"`
	Metadata  map[string]any `json:"metadata"`
	Tags      []string       `json:"tags"`
}

type RegistrationMode string

const (
	JITP            RegistrationMode = "JITP"
	PreRegistration RegistrationMode = "PRE_REGISTRATION"
)

type EnrollmentSettings struct {
	EnrollmentProtocol          EnrollmentProto             `json:"protocol"`
	EnrollmentOptionsESTRFC7030 EnrollmentOptionsESTRFC7030 `json:"est_rfc7030_settings"`
	DeviceProvisionProfile      DeviceProvisionProfile      `json:"device_provisioning_profile"`
	EnrollmentCA                string                      `json:"enrollment_ca"`
	EnableReplaceableEnrollment bool                        `json:"enable_replaceable_enrollment"` //switch-like option that enables enrolling, already enrolled devices
	RegistrationMode            RegistrationMode            `json:"registration_mode"`
	VerifyCSRSignature          bool                        `json:"verify_csr_signature"` //switch-like option that enables CSR signature verification
}

type EnrollmentOptionsESTRFC7030 struct {
	AuthMode                   ESTAuthMode                  `json:"auth_mode"`
	AuthOptionsMTLS            AuthOptionsClientCertificate `json:"client_certificate_settings"`
	AuthOptionsExternalWebhook WebhookCall                  `json:"external_webhook"`
}

type AuthOptionsClientCertificate struct {
	ValidationCAs        []string `json:"validation_cas"`
	ChainLevelValidation int      `json:"chain_level_validation"`
	AllowExpired         bool     `json:"allow_expired"` // switch-like option that allows the use of expired certificates
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

type DMSStats struct {
	TotalDMSs int `json:"total"`
}

type BindIdentityToDeviceOutput struct {
	Certificate *Certificate `json:"certificate"`
	DMS         *DMS         `json:"dms"`
	Device      *Device      `json:"device"`
}
