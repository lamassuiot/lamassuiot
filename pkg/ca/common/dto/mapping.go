package dto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

const (
	StatusValid   = "issued"
	StatusRevoked = "revoked"
	StatusExpired = "expired"
)

type Stats struct {
	IssuedCerts int       `json:"issued_certs"`
	CAs         int       `json:"cas"`
	ScanDate    time.Time `json:"scan_date"`
}

type Cert struct {
	// The status of the CA
	// required: true
	// example: issued | expired
	Status string `json:"status,omitempty"`

	// The serial number of the CA
	// required: true
	// example: 7e:36:13:a5:31:9f:4a:76:10:64:2e:9b:0a:11:07:b7:e6:3e:cf:94
	SerialNumber string `json:"serial_number,omitempty"`

	// The name/alias of the CA
	// required: true
	// example: Lamassu-CA
	Name string `json:"name,omitempty"`

	KeyMetadata PrivateKeyMetadataWithStregth `json:"key_metadata"`

	Subject Subject `json:"subject"`

	CertContent CertContent `json:"certificate"`

	// Expiration period of the new emmited CA
	// required: true
	// example: 262800h
	CaTTL int `json:"ca_ttl,omitempty"`

	EnrollerTTL int `json:"enroller_ttl,omitempty"`

	ValidFrom           string `json:"valid_from"`
	ValidTo             string `json:"valid_to"`
	RevocationTimestamp int64  `json:"revocation_timestamp,omitempty"`
}
type Subject struct {
	// Common name of the CA certificate
	// required: true
	// example: Lamassu-Root-CA1-RSA4096
	CommonName string `json:"common_name" validate:"required"`

	// Organization of the CA certificate
	// required: true
	// example: Lamassu IoT
	Organization string `json:"organization"`

	// Organization Unit of the CA certificate
	// required: true
	// example: Lamassu IoT department 1
	OrganizationUnit string `json:"organization_unit"`

	// Country Name of the CA certificate
	// required: true
	// example: ES
	Country string `json:"country"`

	// State of the CA certificate
	// required: true
	// example: Guipuzcoa
	State string `json:"state"`

	// Locality of the CA certificate
	// required: true
	// example: Arrasate
	Locality string `json:"locality"`
}
type PrivateKeyMetadata struct {
	// Algorithm used to create CA key
	// required: true
	// example: RSA
	KeyType string `json:"type" validate:"oneof='RSA' 'EC'"`

	// Length used to create CA key
	// required: true
	// example: 4096
	KeyBits int `json:"bits"  validate:"required"`
}
type PrivateKeyMetadataWithStregth struct {
	// Algorithm used to create CA key
	// required: true
	// example: RSA
	KeyType string `json:"type" validate:"oneof='RSA' 'EC'"`

	// Length used to create CA key
	// required: true
	// example: 4096
	KeyBits int `json:"bits"`

	// Strength of the key used to the create CA
	// required: true
	// example: low
	KeyStrength string `json:"strength"`
}
type CertContent struct {
	CerificateBase64 string `json:"pem_base64, omitempty"`
	PublicKeyBase64  string `json:"public_key_base64"`
}
type CAType int

const (
	DmsEnroller CAType = iota
	Pki
)

func ParseCAType(s string) (CAType, error) {
	switch s {
	case "dmsenroller":
		return DmsEnroller, nil
	case "pki":
		return Pki, nil
	}
	return -1, errors.New("CAType parsing error")
}

func (c CAType) ToVaultPath() string {
	switch c {
	case DmsEnroller:
		return "_internal/"
	case Pki:
		return "_pki/"
	}
	return "_pki"
}

func (c CAType) String() string {
	switch c {
	case DmsEnroller:
		return "dmsenroller"
	case Pki:
		return "pki"
	}
	return "pki"
}

type KeyType string

const (
	RSA KeyType = "RSA"
	EC  KeyType = "EC"
)

func ParseKeyType(s string) (KeyType, error) {
	switch s {
	case "RSA":
		return RSA, nil
	case "ECDSA":
		return EC, nil
	}
	return "RSA", errors.New("KeyType parsing error")
}

func (c KeyType) String() string {
	switch c {
	case RSA:
		return "RSA"
	case EC:
		return "EC"
	}
	return "RSA"
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

type PaginationOptions struct {
	Page   int `json:"page"`
	Offset int `json:"offset"`
}
type OrderOptions struct {
	Order string `json:"order"`
	Field string `json:"field"`
}

type QueryParameters struct {
	Filter     string            `json:"filter"`
	Order      OrderOptions      `json:"order_options"`
	Pagination PaginationOptions `json:"pagination_options"`
}

const DefaultQueryParam = "{1,50}"
