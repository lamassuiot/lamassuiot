package api

import (
	"crypto/x509"
	"time"

	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lib/pq"
)

type DevicesManagerStats struct {
	DevicesStats map[DeviceStatus]int
	SlotsStats   map[caApi.CertificateStatus]int
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
	KeyStrengthHigh   KeyStrength = "HIGH"
	KeyStrengthMedium KeyStrength = "MEDIUM"
	KeyStrengthLow    KeyStrength = "LOW"
)

func ParseKeyStrength(t string) KeyStrength {
	switch t {
	case "HIGH":
		return KeyStrengthHigh
	case "MEDIUM":
		return KeyStrengthMedium
	case "LOW":
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
	DeviceStatusRequiresAction          DeviceStatus = "REQUIRES_ACTION"           // used if the device has a slot about to expire
	DeviceStatusProvisionedWithWarnings DeviceStatus = "PROVISIONED_WITH_WARNINGS" // used if the device has a slot EXPIRED or revoked
	DeviceStatusDecommissioned          DeviceStatus = "DECOMMISSIONED"
)

func ParseDeviceStatus(t string) DeviceStatus {
	switch t {
	case "PENDING_PROVISIONING":
		return DeviceStatusPendingProvisioning
	case "FULLY_PROVISIONED":
		return DeviceStatusFullyProvisioned
	case "REQUIRES_ACTION":
		return DeviceStatusRequiresAction
	case "PROVISIONED_WITH_WARNINGS":
		return DeviceStatusProvisionedWithWarnings
	case "DECOMMISSIONED":
		return DeviceStatusDecommissioned
	default:
		return DeviceStatusPendingProvisioning
	}
}

type Certificate struct {
	CAName              string
	SerialNumber        string
	Certificate         *x509.Certificate
	Status              caApi.CertificateStatus
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
	ID                 string
	DmsName            string
	Alias              string
	Status             DeviceStatus
	Slots              []*Slot
	AllowNewEnrollment bool
	Description        string
	Tags               []string
	IconName           string
	IconColor          string
	CreationTimestamp  time.Time
}

type LogType string

const (
	LogTypeInfo     LogType = "INFO"
	LogTypeWarn     LogType = "WARN"
	LogTypeCritical LogType = "CRITICAL"
	LogTypeSuccess  LogType = "SUCCESS"
)

type Log struct {
	LogType        LogType
	LogMessage     string
	LogDescription string
	Timestamp      time.Time
}

type DeviceLogs struct {
	DevciceID string
	Logs      []Log
	SlotLogs  map[string][]Log
}

// ---------------------------------------------------------------------

type GetStatsInput struct {
	ForceRefresh bool
}

type GetStatsOutput struct {
	DevicesManagerStats DevicesManagerStats
	ScanDate            time.Time
}

// ---------------------------------------------------------------------

type CreateDeviceInput struct {
	DeviceID    string
	DmsName     string
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
	DeviceID           string
	Alias              string
	Tags               []string
	Description        string
	AllowNewEnrollment bool
	IconColor          string
	IconName           string
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

type GetDevicesByDMSInput struct {
	DmsName         string
	QueryParameters common.QueryParameters
}

type GetDevicesByDMSOutput struct {
	TotalDevices int
	Devices      []Device
}

// ---------------------------------------------------------------------
type IterateDevicesByDMSWithPredicateInput struct {
	DmsName       string          `validate:"required"`
	PredicateFunc func(d *Device) `validate:"required"`
}

type IterateDevicesByDMSWithPredicateOutput struct{}

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
	CertSerialNumber string
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
	DeviceLogs
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
	Status           caApi.CertificateStatus
	RevocationReason string
	CertSerialNumber string
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

type CheckDeviceStatusInput struct {
	DeviceID string
}

type CheckDeviceStatusOutput struct {
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

// ---------------------------------------------------------------------

type ForceReenrollInput struct {
	DeviceID      string `validate:"required"`
	SlotID        string `validate:"required"`
	ForceReenroll bool
}

type ForceReenrollOtput struct {
	DeviceID      string
	SlotID        string
	ForceReenroll bool
	Crt           *x509.Certificate
}

// ---------------------------------------------------------------------

type ImportDeviceCertInput struct {
	DeviceID     string
	SlotID       string
	SerialNumber string
	CaName       string
}

type ImportDeviceCertOutput struct {
	Slot
}

// ---------------------------------------------------------------------
