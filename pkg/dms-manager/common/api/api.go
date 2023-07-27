package api

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
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

type ShadowType string

const (
	ShadowTypeClassic ShadowType = "CLASSIC"
	ShadowTypeNamed   ShadowType = "NAMED"
)

func ParseShadowType(t string) ShadowType {
	switch t {
	case "CLASSIC":
		return ShadowTypeClassic
	case "NAMED":
		return ShadowTypeNamed
	default:
		return ShadowTypeNamed
	}
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

type DeviceManufacturingService struct {
	Name                 string
	Status               DMSStatus
	CreationTimestamp    time.Time
	CloudDMS             bool
	Aws                  AwsSpecification
	IdentityProfile      *IdentityProfile
	RemoteAccessIdentity *RemoteAccessIdentity
}

type AwsSpecification struct {
	ShadowType ShadowType
}

type RemoteAccessIdentity struct {
	ExternalKeyGeneration    bool
	SerialNumber             string
	KeyMetadata              KeyStrengthMetadata
	Subject                  Subject
	AuthorizedCAs            []string
	CertificateString        string
	Certificate              *x509.Certificate
	CertificateRequestString string
	CertificateRequest       *x509.CertificateRequest
}

type IdentityProfile struct {
	GeneralSettings        IdentityProfileGeneralSettings
	EnrollmentSettings     IdentityProfileEnrollmentSettings
	ReerollmentSettings    IdentityProfileReenrollmentSettings
	CADistributionSettings IdentityProfileCADistributionSettings
	PublishToAWS           bool
}

type EnrollmentMode string

const (
	EnrollmentModeEST EnrollmentMode = "EST"
)

type IdentityProfileGeneralSettings struct {
	EnrollmentMode EnrollmentMode
}

type ESTAuthenticationMode string

const (
	BootstrapMutualTLS ESTAuthenticationMode = "BOOTSTRAP_MTLS"
)

type IdentityProfileEnrollmentSettings struct {
	AuthenticationMode     ESTAuthenticationMode
	AllowNewAutoEnrollment bool
	Tags                   []string
	Icon                   string
	Color                  string
	AuthorizedCA           string
	BootstrapCAs           []string
}

type IdentityProfileReenrollmentSettings struct {
	AllowExpiredRenewal       bool
	PreventiveRenewalInterval time.Duration
}

type StaticCA struct {
	ID          string
	Certificate *x509.Certificate
}

type IdentityProfileCADistributionSettings struct {
	IncludeAuthorizedCA        bool
	IncludeBootstrapCAs        bool
	IncludeLamassuDownstreamCA bool
	ManagedCAs                 []string
	StaticCAs                  []StaticCA
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

type UpdateDMSInput struct {
	DeviceManufacturingService
}

type UpdateDMSOutput struct {
	DeviceManufacturingService
}

// ----------------------------------------------

type CreateDMSInput struct {
	DeviceManufacturingService
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
