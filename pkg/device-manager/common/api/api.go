package api

import (
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lib/pq"
)

type SlotsStats struct {
	PendingEnrollment int
	Active            int
	Expired           int
	Revoked           int
}

type DevicesStats struct {
	PendingProvisioning     int
	FullyProvisioned        int
	PartiallyProvisioned    int
	ProvisionedWithWarnings int
	Decommisioned           int
}

type DevicesManagerStats struct {
	DevicesStats DevicesStats
	SlotsStats   SlotsStats
}

type KeyType string

const (
	RSA   KeyType = "RSA"
	ECDSA KeyType = "ECDSA"
)

func ParseKeyType(s string) KeyType {
	switch s {
	case "RSA":
		return RSA
	case "ECDSA":
		return ECDSA
	}

	return "RSA"
}

type KeyStrength string

const (
	KeyStrengthHigh   KeyStrength = "high"
	KeyStrengthMedium KeyStrength = "medium"
	KeyStrengthLow    KeyStrength = "low"
)

func ParseKeyStrength(t string) KeyStrength {
	switch t {
	case "high":
		return KeyStrengthHigh
	case "medium":
		return KeyStrengthMedium
	case "low":
		return KeyStrengthLow

	default:
		return KeyStrengthLow
	}
}

type KeyMetadata struct {
	KeyType KeyType
	KeyBits int
}

type KeyStrengthMetadata struct {
	KeyType     KeyType
	KeyBits     int
	KeyStrength KeyStrength
}

type Subject struct {
	CommonName       string
	Organization     string
	OrganizationUnit string
	Country          string
	State            string
	Locality         string
}

type DeviceStatus string

const (
	DeviceStatusPendingProvisioning     DeviceStatus = "PENDING_PROVISIONING"      // used if all the device slots are pending enrollment
	DeviceStatusFullyProvisioned        DeviceStatus = "FULLY_PROVISIONED"         // used if all the device slots are active
	DeviceStatusPartiallyProvisioned    DeviceStatus = "PARTIALLY_PROVISIONED"     // used if the device has a slot in the pending enrollment
	DeviceStatusProvisionedWithWarnings DeviceStatus = "PROVISIONED_WITH_WARNINGS" // used if the device has a slot expired or revoked
	DeviceStatusDecommissioned          DeviceStatus = "DECOMMISSIONED"
)

func ParseDeviceStatus(t string) DeviceStatus {
	switch t {
	case "PENDING_PROVISIONING":
		return DeviceStatusPendingProvisioning
	case "FULLY_PROVISIONED":
		return DeviceStatusFullyProvisioned
	case "PARTIALLY_PROVISIONED":
		return DeviceStatusPartiallyProvisioned
	case "PROVISIONED_WITH_WARNINGS":
		return DeviceStatusProvisionedWithWarnings
	case "DECOMMISSIONED":
		return DeviceStatusDecommissioned
	default:
		return DeviceStatusPendingProvisioning
	}
}

type CertificateStatus string

const (
	CertificateStatusActive        CertificateStatus = "ACTIVE"
	CertificateStatusAboutToExpire CertificateStatus = "ABOUT_TO_EXPIRE"
	CertificateStatusExpired       CertificateStatus = "EXPIRED"
	CertificateStatusRevoked       CertificateStatus = "REVOKED"
)

func ParseCertificateStatus(t string) CertificateStatus {
	switch t {
	case "ACTIVE":
		return CertificateStatusActive
	case "ABOUT_TO_EXPIRE":
		return CertificateStatusAboutToExpire
	case "EXPIRED":
		return CertificateStatusExpired
	case "REVOKED":
		return CertificateStatusRevoked
	default:
		return CertificateStatusActive
	}
}

type Certificate struct {
	CAName              string
	SerialNumber        string
	Certificate         *x509.Certificate
	Status              CertificateStatus
	KeyMetadata         KeyStrengthMetadata
	Subject             Subject
	ValidFrom           time.Time
	ValidTo             time.Time
	RevocationTimestamp pq.NullTime
	RevocationReason    string
}

type Slot struct {
	ID                  string
	ActiveCertificate   *Certificate
	ArchiveCertificates []*Certificate
}

type Device struct {
	ID          string
	Alias       string
	Status      DeviceStatus
	Slots       []*Slot
	Description string
	Tags        []string
	IconName    string
	IconColor   string
}

type DeviceLog struct {
	ID         string
	DeviceID   string
	LogType    string
	LogMessage string
	Timestamp  time.Time
}

// ---------------------------------------------------------------------

type GetStatsInput struct {
	ForceRefresh bool
}

type GetStatsOutput struct {
	DevicesManagerStats
}

// ---------------------------------------------------------------------

type CreateDeviceInput struct {
	DeviceID    string
	Alias       string
	Tags        []string
	IconColor   string
	Description string
	IconName    string
}

type CreateDeviceOutput struct {
	Device
}

// ---------------------------------------------------------------------

type UpdateDeviceMetadataInput struct {
	DeviceID    string
	Alias       string
	Tags        []string
	Description string
	IconColor   string
	IconName    string
}

type UpdateDeviceMetadataOutput struct {
	Device
}

// ---------------------------------------------------------------------

type GetDevicesInput struct {
	QueryParameters common.QueryParameters
}

type GetDevicesOutput struct {
	TotalDevices int
	Devices      []Device
}

// ---------------------------------------------------------------------

type GetDeviceByIdInput struct {
	DeviceID string
}

type GetDeviceByIdOutput struct {
	Device
}

// ---------------------------------------------------------------------

type DecommisionDeviceInput struct {
	DeviceID string
}

type DecommisionDeviceOutput struct {
	Device
}

// ---------------------------------------------------------------------

type RevokeActiveCertificateInput struct {
	DeviceID         string
	SlotID           string
	RevocationReason string
}

type RevokeActiveCertificateOutput struct {
	Slot
}

// ---------------------------------------------------------------------

type RotateActiveCertificateInput struct {
	DeviceID       string
	SlotID         string
	NewCertificate *x509.Certificate
}

type RotateActiveCertificateOutput struct {
	Slot
}

// ---------------------------------------------------------------------

type GetDeviceLogsInput struct {
	DeviceID string
}

type GetDeviceLogsOutput struct {
	TotalLogs int
	Logs      []DeviceLog
}

// ---------------------------------------------------------------------

type AddDeviceLogInput struct {
	DeviceID   string
	LogType    string
	LogMessage string
	Timestamp  time.Time
}

type AddDeviceLogOutput struct {
}

// ---------------------------------------------------------------------

type AddDeviceSlotInput struct {
	DeviceID          string
	SlotID            string
	ActiveCertificate *x509.Certificate
}

type AddDeviceSlotOutput struct {
	Slot
}

// ---------------------------------------------------------------------

type UpdateActiveCertificateStatusInput struct {
	DeviceID         string
	SlotID           string
	Status           CertificateStatus
	RevocationReason string
}

type UpdateActiveCertificateStatusOutput struct {
	Slot
}

// ---------------------------------------------------------------------

type IterateDevicesWithPredicateInput struct {
	PredicateFunc func(c *Device)
}

type IterateDevicesWithPredicateOutput struct{}

// ---------------------------------------------------------------------

type CheckAndUpdateDeviceStatusInput struct {
	DeviceID string
}

type CheckAndUpdateDeviceStatusOutput struct {
	Device
}

// ---------------------------------------------------------------------

type IsDMSAuthorizedToEnrollInput struct {
	DMSName string
	CAName  string
}

type IsDMSAuthorizedToEnrollOutput struct {
	IsAuthorized bool
}
