package api

import (
	"crypto/x509"
	"errors"

	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lib/pq"
)

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

type CAType string

const (
	CATypeDMSEnroller CAType = "dms_enroller"
	CATypePKI         CAType = "pki"
)

func ParseCAType(t string) CAType {
	switch t {
	case "pki":
		return CATypePKI
	case "dms_enroller":
		return CATypeDMSEnroller
	}

	return CATypePKI
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

type DMSStatus string

const (
	DMSStatusPendingApproval DMSStatus = "PENDING_APPROVAL"
	DMSStatusRejected        DMSStatus = "REJECTED"
	DMSStatusApproved        DMSStatus = "APPROVED"
	DMSStatusExpired         DMSStatus = "EXPIRED"
	DMSStatusRevoked         DMSStatus = "REVOKED"
)

func ParseDMSStatus(status string) (DMSStatus, error) {
	switch status {
	case "PENDING_APPROVAL":
		return DMSStatusPendingApproval, nil
	case "APPROVED":
		return DMSStatusApproved, nil
	case "REJECTED":
		return DMSStatusRejected, nil
	case "REVOKED":
		return DMSStatusRevoked, nil
	case "EXPIRED":
		return DMSStatusExpired, nil
	default:
		return "", errors.New("invalid dms status")
	}
}

type X509Asset struct {
	Certificate        *x509.Certificate
	CertificateRequest *x509.CertificateRequest
	IsCertificate      bool
}

type DeviceManufacturingService struct {
	Name                      string
	Status                    DMSStatus
	SerialNumber              string
	KeyMetadata               KeyStrengthMetadata
	Subject                   Subject
	AuthorizedCAs             []string
	BootstrapCAs              []string
	HostCloudDMS              bool
	CreationTimestamp         pq.NullTime
	LastStatusUpdateTimestamp pq.NullTime
	X509Asset                 X509Asset
}

// ----------------------------------------------

type GetDMSByNameInput struct {
	Name string
}

type GetDMSByNameOutput struct {
	DeviceManufacturingService
}

// ----------------------------------------------

type GetDMSsInput struct {
	QueryParameters common.QueryParameters
}

type GetDMSsOutput struct {
	TotalDMSs int
	DMSs      []DeviceManufacturingService
}

// ----------------------------------------------

type CreateDMSWithCertificateRequestInput struct {
	CertificateRequest *x509.CertificateRequest
	BootstrapCAs       []string
}

type CreateDMSWithCertificateRequestOutput struct {
	DeviceManufacturingService
}

// ----------------------------------------------

type CreateDMSInput struct {
	Subject      Subject
	KeyMetadata  KeyMetadata
	BootstrapCAs []string
	HostCloudDMS bool
}

type CreateDMSOutput struct {
	DMS        DeviceManufacturingService
	PrivateKey interface{}
}

// ----------------------------------------------

type UpdateDMSStatusInput struct {
	Name   string
	Status DMSStatus
}

type UpdateDMSStatusOutput struct {
	DeviceManufacturingService
}

// ----------------------------------------------

type UpdateDMSAuthorizedCAsInput struct {
	Name          string
	AuthorizedCAs []string
}

type UpdateDMSAuthorizedCAsOutput struct {
	DeviceManufacturingService
}

// ---------------------------------------------------------------------

type IterateDMSsWithPredicateInput struct {
	PredicateFunc func(c *DeviceManufacturingService)
}

type IterateDMSsWithPredicateOutput struct {
}
