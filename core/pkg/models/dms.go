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

// DMSSettings is protocol-scoped: Protocol selects the enrollment protocol, and
// exactly one of EST/CMP carries every setting for it. The two containers are
// mutually exclusive — normalizeProtocolSettings (backend/pkg/services/
// dmsmanager.go) allocates the selected one and nils the other on every
// create/update, so any DMS read back from storage has precisely one non-nil.
//
// Settings that both protocols happen to need (CA distribution, the enrollment
// CA, the issuance profile, the re-enrollment monitoring deltas) are duplicated
// into each container rather than hoisted to a shared block: a DMS only ever
// speaks one protocol, so there is no configuration to share, and keeping the
// containers self-contained means the JSON for a given protocol reads top to
// bottom with nothing to cross-reference. Consumers that are protocol-agnostic
// (CACerts, BindIdentityToDevice, resolveIssuanceProfile) switch on Protocol.
type DMSSettings struct {
	Protocol EnrollmentProto `json:"protocol"`
	EST      *ESTSettings    `json:"est_settings,omitempty"`
	CMP      *CMPSettings    `json:"cmp_settings,omitempty"`
}

type EnrollmentProto string

const (
	EST EnrollmentProto = "EST_RFC7030"
	CMP EnrollmentProto = "CMP_RFC9483"
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

// CommonEnrollmentSettings holds the enrollment knobs that are identical for
// both protocols. It is embedded into ESTEnrollmentSettings and
// CMPEnrollmentSettings so the fields sit flat in each protocol's JSON while
// still being declared once.
type CommonEnrollmentSettings struct {
	DeviceProvisionProfile      DeviceProvisionProfile `json:"device_provisioning_profile"`
	EnrollmentCA                string                 `json:"enrollment_ca"`
	EnableReplaceableEnrollment bool                   `json:"enable_replaceable_enrollment"` //switch-like option that enables enrolling, already enrolled devices
	RegistrationMode            RegistrationMode       `json:"registration_mode"`
	VerifyCSRSignature          bool                   `json:"verify_csr_signature"` //switch-like option that enables CSR signature verification
}

// CommonReEnrollmentSettings holds the re-enrollment knobs that are identical
// for both protocols, including the two monitoring deltas that the
// protocol-agnostic BindIdentityToDevice materializes onto CA metadata.
type CommonReEnrollmentSettings struct {
	AdditionalValidationCAs     []string     `json:"additional_validation_cas"`
	RevokeOnReEnrollment        bool         `json:"revoke_on_reenrollment"`
	ReEnrollmentDelta           TimeDuration `json:"reenrollment_delta"`
	EnableExpiredRenewal        bool         `json:"enable_expired_renewal"`
	PreventiveReEnrollmentDelta TimeDuration `json:"preventive_delta"` // (expiration time - delta < time.now) at witch point an event is issued notify its time to reenroll
	CriticalReEnrollmentDelta   TimeDuration `json:"critical_delta"`   // (expiration time - delta < time.now) at witch point an event is issued notify critical status
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
