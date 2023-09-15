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
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Metadata        map[string]string `json:"metadata"`
	CreationDate    time.Time         `json:"creation_ts"`
	IdentityProfile IdentityProfile   `json:"identity_profile"`
}

type IdentityProfile struct {
	EnrollmentSettings     EnrollmentSettings     `json:"enrollment_settings"`
	ReEnrollmentSettings   ReEnrollmentSettings   `json:"reenrollment_settings"`
	CADistributionSettings CADistributionSettings `json:"ca_distribution_settings"`
}

type EnrollmentProto string

const (
	EST EnrollmentProto = "EST_RFC7030"
)

type DeviceProvisionSettings struct {
	Icon      string            `json:"icon"`
	IconColor string            `json:"icon_color"`
	Metadata  map[string]string `json:"metadata"`
	Tags      []string          `json:"tags"`
}

type EnrollmentSettings struct {
	EnrollmentProtocol          EnrollmentProto             `json:"protocol"`
	EnrollmentOptionsESTRFC7030 EnrollmentOptionsESTRFC7030 `json:"estrfc7030_options"`
	DeviceProvisionSettings     DeviceProvisionSettings     `json:"device_provisioning"`
	AuthorizedCA                string                      `json:"authorized_ca"`
	AllowNewEnrollment          bool                        `json:"allow_new_enrollment"` //switch-like option that enables enrolling, already enrolled devices
	JustInTime                  bool                        `json:"jit"`
	PreRegistryEnrollment       bool                        `json: "pre_registry_enrollment"`
}

type EnrollmentOptionsESTRFC7030 struct {
	AuthMode        ESTAuthMode `json:"auth_mode"`
	AuthOptionsMTLS struct {
		ValidationCAs []string `json:"validation_cas"`
	} `json:"mutual_tls_options"`
}

type ReEnrollmentSettings struct {
	AdditionalValidationCAs     []string     `json:"additional_validation_cas"`
	AllowedReenrollmentDelta    TimeDuration `json:"allowed_reenrollment_detlta"`
	AllowExpiredRenewal         bool         `json:"allow_expired_renewal"`
	PreventiveReenrollmentDelta TimeDuration `json:"preventive_delta"` // (expiration time - delta < time.now) at witch point an event is issued notify its time to reenroll
	CriticalReenrollmentDetla   TimeDuration `json:"critical_delta"`   // (expiration time - delta < time.now) at witch point an event is issued notify critical status
}

type CADistributionSettings struct {
	IncludeLamassuSystemCA bool     `json:"include_system_ca"`
	IncludeAuthorizedCA    bool     `json:"include_authorized_ca"`
	ManagedCAs             []string `json:"managed_cas"`
}

type StaticCA struct {
	Certificate *X509Certificate `json:"certificate"`
	Name        string           `json:"name"`
	UpdateTS    time.Time        `json:"update_ts"`
}
