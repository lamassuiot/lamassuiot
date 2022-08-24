package api

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

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

type EngineProviderInfo struct {
	Provider          string
	CryptokiVersion   string
	Manufacturer      string
	Model             string
	Library           string
	SupportedKeyTypes []SupportedKeyTypeInfo
}

type SupportedKeyTypeInfo struct {
	Type        string
	MinimumSize int
	MaximumSize int
}

type CertificateStatus string

const (
	StatusActive        CertificateStatus = "ACTIVE"
	StatusExpired       CertificateStatus = "EXPIRED"
	StatusRevoked       CertificateStatus = "REVOKED"
	StatusAboutToExpire CertificateStatus = "ABOUT_TO_EXPIRE"
)

func ParseCertificateStatus(t string) CertificateStatus {
	switch t {
	case "ACTIVE":
		return StatusActive
	case "EXPIRED":
		return StatusExpired
	case "REVOKED":
		return StatusRevoked
	case "ABOUT_TO_EXPIRE":
		return StatusAboutToExpire
	default:
		return StatusActive
	}
}

type PrivateKey struct {
	Key     interface{}
	KeyType KeyType
}

func (pk *PrivateKey) GetPEMString() (string, error) {
	switch key := pk.Key.(type) {
	case *rsa.PrivateKey:
		bytes, _ := x509.MarshalPKCS8PrivateKey(key)
		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: bytes,
			},
		)
		return string(pemdata), nil
	case *ecdsa.PrivateKey:
		x509Encoded, _ := x509.MarshalECPrivateKey(key)
		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: x509Encoded,
			},
		)
		return string(pemdata), nil
	default:
		return "", errors.New("unsupported format")
	}
}

type Certificate struct {
	CAName              string
	Status              CertificateStatus
	Certificate         *x509.Certificate
	SerialNumber        string
	KeyMetadata         KeyStrengthMetadata
	Subject             Subject
	ValidFrom           time.Time
	ValidTo             time.Time
	RevocationTimestamp pq.NullTime
	RevocationReason    string
}

type CACertificate struct {
	Certificate
	IssuanceDuration time.Duration
}

// ---------------------------------------------------------------------
type GetStatsInput struct {
	ForceRefesh bool
}

type GetStatsOutput struct {
	IssuedCerts int
	CAs         int
	ScanDate    time.Time
}

// ---------------------------------------------------------------------
type CreateCAInput struct {
	CAType           CAType
	Subject          Subject
	KeyMetadata      KeyMetadata
	CADuration       time.Duration
	IssuanceDuration time.Duration
}

type CreateCAOutput struct {
	CACertificate
}

// ---------------------------------------------------------------------
type GetCAsInput struct {
	CAType          CAType
	QueryParameters common.QueryParameters
}

type GetCAsOutput struct {
	TotalCAs int
	CAs      []CACertificate
}

// ---------------------------------------------------------------------
type GetCAByNameInput struct {
	CAType CAType
	CAName string
}

type GetCAByNameOutput struct {
	CACertificate
}

// ---------------------------------------------------------------------

type ImportCAInput struct {
	CAType           CAType
	Certificate      *x509.Certificate
	PrivateKey       *PrivateKey
	IssuanceDuration time.Duration
}

type ImportCAOutput struct {
	CACertificate
}

// ---------------------------------------------------------------------

type UpdateCAStatusInput struct {
	CAType CAType
	CAName string
	Status CertificateStatus
}

type UpdateCAStatusOutput struct {
	CACertificate
}

// ---------------------------------------------------------------------

type RevokeCAInput struct {
	CAType           CAType
	CAName           string
	RevocationReason string
}

type RevokeCAOutput struct {
	CACertificate
}

// ---------------------------------------------------------------------

type SignCertificateRequestInput struct {
	CAType                    CAType
	CAName                    string
	CertificateSigningRequest *x509.CertificateRequest
	CommonName                string
	SignVerbatim              bool
}

type SignCertificateRequestOutput struct {
	Certificate   *x509.Certificate
	CACertificate *x509.Certificate
}

// ---------------------------------------------------------------------

type RevokeCertificateInput struct {
	CAType                  CAType
	CAName                  string
	CertificateSerialNumber string
	RevocationReason        string
}

type RevokeCertificateOutput struct {
	Certificate
}

// ---------------------------------------------------------------------

type UpdateCertificateStatusInput struct {
	CAType                  CAType
	CAName                  string
	CertificateSerialNumber string
	Status                  CertificateStatus
}

type UpdateCertificateStatusOutput struct {
	Certificate
}

// ---------------------------------------------------------------------

type GetCertificateBySerialNumberInput struct {
	CAType                  CAType
	CAName                  string
	CertificateSerialNumber string
}

type GetCertificateBySerialNumberOutput struct {
	Certificate
}

// ---------------------------------------------------------------------

type GetCertificatesInput struct {
	CAType          CAType
	CAName          string
	QueryParameters common.QueryParameters
}

type GetCertificatesOutput struct {
	TotalCertificates int
	Certificates      []Certificate
}

// ---------------------------------------------------------------------

type IterateCertificatesWithPredicateInput struct {
	CAType        CAType
	CAName        string
	PredicateFunc func(c *Certificate)
}

type IterateCertificatesWithPredicateOutput struct {
}

// ---------------------------------------------------------------------

type IterateCAsWithPredicateInput struct {
	CAType        CAType
	PredicateFunc func(c *CACertificate)
}

type IterateCAsWithPredicateOutput struct {
}

// ---------------------------------------------------------------------

type CheckAndUpdateCACertificateStatusInput struct {
	CAType CAType
	CAName string
}

type CheckAndUpdateCACertificateStatusOutput struct {
	CACertificate
}
