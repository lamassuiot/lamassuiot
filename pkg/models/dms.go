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
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	Status               DMSStatus             `json:"status"`
	CloudDMS             bool                  `json:"cloud_dms"`
	Metadata             map[string]string     `json:"metadata"`
	Tags                 []string              `json:"tags"`
	CreationDate         time.Time             `json:"creation_ts"`
	IdentityProfile      *IdentityProfile      `json:"identity_profile"`
	RemoteAccessIdentity *RemoteAccessIdentity `json:"remote_access_identity"`
}

type RemoteAccessIdentity struct {
	Certificate           *Certificate            `json:"certificate"`
	ExternalKeyGeneration bool                    `json:"external_key"`
	CertificateRequest    *X509CertificateRequest `json:"csr"`
}

type IdentityProfile struct {
	EnrollmentSettings     EnrollmentSettings     `json:"enrollment_settings"`
	CADistributionSettings CADistributionSettings `json:"ca_distribution_settings"`
}

type EnrollmentAuthenticationMode string

const (
	NoAuth               EnrollmentAuthenticationMode = "NO_AUTH"
	BootstrapPSK         EnrollmentAuthenticationMode = "GENERIC_PSK"
	BootstrapCertificate EnrollmentAuthenticationMode = "BOOTSTRAP_CERT"
)

type DeviceProvisionSettings struct {
	Icon         string                 `json:"icon"`
	IconColor    string                 `json:"icon_color"`
	Metadata     map[string]string      `json:"metadata"`
	Tags         []string               `json:"tags"`
	ExtraSlots   map[string]SlotProfile `json:"extra_slots"` //slot ID => lambda-esk ID runner (maybe with open FaaS? // AwsLambdas) ?
	IdentitySlot IdentitySlot
}

type IdentitySlot struct {
	PreventiveReenrollmentDelta TimeDuration `json:"preventive_reenrollment_delta"` // (expiration time - delta < time.now) at witch point an event is issued notify its time to reenroll
	CriticalReenrollmentDetla   TimeDuration `json:"critical_delta"`                // (expiration time - delta < time.now) at witch point an event is issued notify critical status
}

type SlotProfile struct {
	Confidential                bool             `json:"confidential"`
	PreventiveReenrollmentDelta TimeDuration     `json:"preventive_reenrollment_delta"` // (expiration time - delta < time.now) at witch point an event is issued notify its time to reenroll
	CriticalDetla               TimeDuration     `json:"critical_delta"`                // (expiration time - delta < time.now) at witch point an event is issued notify critical status
	Type                        CryptoSecretType `json:"type"`
	Secret                      interface{}      `json:"secret"`
	Hash                        string           `json:"hash"`
	HashAlgorithm               string           `json:"hash_alg"`
	UpdateTS                    time.Time        `json:"update_ts"`
	RemoteFunc                  *RemoteFuncExec  `json:"lambda"`
}

type EnrollmentSettings struct {
	AuthenticationMode      EnrollmentAuthenticationMode `json:"auth_mode"`
	DeviceProvisionSettings DeviceProvisionSettings      `json:"device_provisioning"`
	AuthorizedCAs           []string                     `json:"authorized_cas"`
	BootstrapCAs            []string                     `json:"bootstrap_cas"`
	BootstrapPSK            string                       `json:"bootstap_psk"`
}

type CADistributionSettings struct {
	IncludeLamassuSystemCA bool        `json:"include_system_ca"`
	IncludeBootstrapCAs    bool        `json:"include_bootstrap_cas"`
	IncludeAuthorizedCAs   bool        `json:"include_authorized_cas"`
	ManagedCAs             []string    `json:"managed_cas"`
	StaticCAs              []StaticCA  `json:"static_cas"`
	DynamicCAs             []DynamicCA `json:"dynamic_cas"`
}

type StaticCA struct {
	Certificate *X509Certificate `json:"certificate"`
	Name        string           `json:"name"`
	UpdateTS    time.Time        `json:"update_ts"`
}

type DynamicCA struct {
	LambdaID string    `json:"lambda"`
	Name     string    `json:"name"`
	UpdateTS time.Time `json:"update_ts"`
}
