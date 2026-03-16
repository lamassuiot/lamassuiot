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
	IssuanceProfileID      string                 `json:"issuance_profile_id"`
	IssuanceProfile        *IssuanceProfile       `json:"issuance_profile"`
}

type EnrollmentProto string

const (
	EST EnrollmentProto = "EST_RFC7030"
	CMP EnrollmentProto = "CMP_RFC4210"
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
	EnrollmentOptionsLWCRFC9483 EnrollmentOptionsLWCRFC9483 `json:"lwc_rfc9483_settings"`
	DeviceProvisionProfile      DeviceProvisionProfile      `json:"device_provisioning_profile"`
	EnrollmentCA                string                      `json:"enrollment_ca"`
	EnableReplaceableEnrollment bool                        `json:"enable_replaceable_enrollment"` //switch-like option that enables enrolling, already enrolled devices
	RegistrationMode            RegistrationMode            `json:"registration_mode"`
	VerifyCSRSignature          bool                        `json:"verify_csr_signature"` //switch-like option that enables CSR signature verification
}
type AuthOptionsClientCertificate struct {
	ValidationCAs        []string `json:"validation_cas"`
	ChainLevelValidation int      `json:"chain_level_validation"`
	AllowExpired         bool     `json:"allow_expired"` // switch-like option that allows the use of expired certificates
}

type DMSStats struct {
	TotalDMSs int `json:"total"`
}

type BindIdentityToDeviceOutput struct {
	Certificate *Certificate `json:"certificate"`
	DMS         *DMS         `json:"dms"`
	Device      *Device      `json:"device"`
}
