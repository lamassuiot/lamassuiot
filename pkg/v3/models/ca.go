package models

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"time"
)

type CAType string

const (
	CATypeManaged  CAType = "MANAGED"
	CATypeImported CAType = "IMPORTED"
	CATypeExternal CAType = "EXTERNAL"
)

type InternalCA string

const (
	CALocalRA InternalCA = "_lms-lra"
)

type ExpirationTimeRef string

var (
	Duration ExpirationTimeRef = "Duration"
	Time     ExpirationTimeRef = "Time"
)

type CertificateStatus string

const (
	StatusActive             CertificateStatus = "ACTIVE"
	StatusExpired            CertificateStatus = "EXPIRED"
	StatusRevoked            CertificateStatus = "REVOKED"
	StatusNearingExpiration  CertificateStatus = "NEARING_EXPIRATION"
	StatusCriticalExpiration CertificateStatus = "CRITICAL_EXPIRATION"
)

type Certificate struct {
	Metadata            map[string]interface{} `json:"metadata" gorm:"serializer:json"`
	IssuerCAMetadata    IssuerCAMetadata       `json:"issuer_metadata"  gorm:"embedded;embeddedPrefix:issuer_meta_"`
	Status              CertificateStatus      `json:"status"`
	Fingerprint         string                 `json:"fingerprint"`
	Certificate         *X509Certificate       `json:"certificate"`
	SerialNumber        string                 `json:"serial_number"`
	KeyMetadata         KeyStrengthMetadata    `json:"key_metadata" gorm:"embedded;embeddedPrefix:key_strength_meta_"`
	Subject             Subject                `json:"subject" gorm:"embedded;embeddedPrefix:subject_"`
	ValidFrom           time.Time              `json:"valid_from"`
	ValidTo             time.Time              `json:"valid_to"`
	RevocationTimestamp time.Time              `json:"revocation_timestamp"`
}

type CAMetadata struct {
	Name string `json:"name"`
	Type CAType `json:"type"`
}

type Expiration struct {
	Type     ExpirationTimeRef `json:"type"`
	Duration *TimeDuration     `json:"duration"`
	Time     *time.Time        `json:"time"`
}

type IssuerCAMetadata struct {
	SerialNumber string `json:"serial_number"`
	CAID         string `json:"ca_name"`
}

type CACertificate struct {
	Certificate
	ID                    string                 `json:"id" gorm:"primaryKey"`
	Metadata              map[string]interface{} `json:"metadata" gorm:"serializer:json"`
	IssuanceExpirationRef Expiration             `json:"issuance_expiration" gorm:"serializer:json"`
	CARef                 CAMetadata             `json:"ca_ref" gorm:"embedded;embeddedPrefix:ca_ref_"`
	CreationTS            time.Time              `json:"creation_ts"`
}

type CAStats struct {
	CACertificatesStats struct {
		TotalCAs                 int                       `json:"total"`
		CAsDistributionPerEngine map[string]int            `json:"engine_distribution"`
		CAsStatus                map[CertificateStatus]int `json:"status_distribution"`
	} `json:"cas"`
	CertificatesStats struct {
		TotalCertificates            int                       `json:"total"`
		CertificateDistributionPerCA map[string]int            `json:"ca_distribution"`
		CertificateStatus            map[CertificateStatus]int `json:"status_distribution"`
	} `json:"certificates"`
}

type SigningMessageType string

const (
	Digest SigningMessageType = "DIGEST"
	RAW    SigningMessageType = "RAW"
)

type SigningAlgorithm string

const (
	RSASSA_PSS_SHA_256        SigningAlgorithm = "RSASSA_PSS_SHA_256"
	RSASSA_PSS_SHA_384        SigningAlgorithm = "RSASSA_PSS_SHA_384"
	RSASSA_PSS_SHA_512        SigningAlgorithm = "RSASSA_PSS_SHA_512"
	RSASSA_PKCS1_V1_5_SHA_256 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	RSASSA_PKCS1_V1_5_SHA_384 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_384"
	RSASSA_PKCS1_V1_5_SHA_512 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_512"
	ECDSA_SHA_256             SigningAlgorithm = "ECDSA_SHA_256"
	ECDSA_SHA_384             SigningAlgorithm = "ECDSA_SHA_384"
	ECDSA_SHA_512             SigningAlgorithm = "ECDSA_SHA_512"
)

func (alg SigningAlgorithm) GetHashFunc() crypto.Hash {
	switch alg {
	case RSASSA_PSS_SHA_256, RSASSA_PKCS1_V1_5_SHA_256, ECDSA_SHA_256:
		return crypto.SHA256
	case RSASSA_PSS_SHA_384, RSASSA_PKCS1_V1_5_SHA_384, ECDSA_SHA_384:
		return crypto.SHA384
	case RSASSA_PSS_SHA_512, RSASSA_PKCS1_V1_5_SHA_512, ECDSA_SHA_512:
		return crypto.SHA512
	default:
		return crypto.SHA512
	}

}

func (alg SigningAlgorithm) GetSignerOpts() crypto.SignerOpts {
	switch alg {
	case RSASSA_PSS_SHA_256, RSASSA_PSS_SHA_384, RSASSA_PSS_SHA_512:
		return &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       alg.GetHashFunc(),
		}
	case RSASSA_PKCS1_V1_5_SHA_256, RSASSA_PKCS1_V1_5_SHA_384, RSASSA_PKCS1_V1_5_SHA_512:
		return alg.GetHashFunc()
	case ECDSA_SHA_256, ECDSA_SHA_384, ECDSA_SHA_512:
		return alg.GetHashFunc()
	default:
		return alg.GetHashFunc()
	}
}
func (alg SigningAlgorithm) GetKeyType() KeyType {
	switch alg {
	case RSASSA_PSS_SHA_256, RSASSA_PSS_SHA_384, RSASSA_PSS_SHA_512, RSASSA_PKCS1_V1_5_SHA_256, RSASSA_PKCS1_V1_5_SHA_384, RSASSA_PKCS1_V1_5_SHA_512:
		return KeyType(x509.RSA)
	case ECDSA_SHA_256, ECDSA_SHA_384, ECDSA_SHA_512:
		return KeyType(x509.ECDSA)
	default:
		return KeyType(x509.RSA)
	}
}

func (alg SigningAlgorithm) GenerateDigest(rawMsg []byte) []byte {
	switch alg {
	case RSASSA_PSS_SHA_256, RSASSA_PKCS1_V1_5_SHA_256, ECDSA_SHA_256:
		hashed := sha256.Sum256(rawMsg)
		return hashed[:]
	case RSASSA_PSS_SHA_384, RSASSA_PKCS1_V1_5_SHA_384, ECDSA_SHA_384:
		hashed := sha512.Sum384(rawMsg)
		return hashed[:]
	case RSASSA_PSS_SHA_512, RSASSA_PKCS1_V1_5_SHA_512, ECDSA_SHA_512:
		hashed := sha512.Sum512(rawMsg)
		return hashed[:]
	default:
		hashed := sha512.Sum512(rawMsg)
		return hashed[:]
	}
}

func (alg SigningAlgorithm) VerifySignature(pubKey crypto.PublicKey, digest, signature []byte) error {
	switch alg {
	case RSASSA_PSS_SHA_256, RSASSA_PSS_SHA_384, RSASSA_PSS_SHA_512:
		switch pub := pubKey.(type) {
		case *rsa.PublicKey:
			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       alg.GetHashFunc(),
			}
			return rsa.VerifyPSS(pub, alg.GetHashFunc(), digest, signature, opts)
		default:
			return fmt.Errorf("invalid public key type for RSA signature scheme")
		}

	case RSASSA_PKCS1_V1_5_SHA_256, RSASSA_PKCS1_V1_5_SHA_384, RSASSA_PKCS1_V1_5_SHA_512:
		switch pub := pubKey.(type) {
		case *rsa.PublicKey:
			return rsa.VerifyPKCS1v15(pub, alg.GetHashFunc(), digest, signature)
		default:
			return fmt.Errorf("invalid public key type for RSA signature scheme")
		}

	case ECDSA_SHA_256, ECDSA_SHA_384, ECDSA_SHA_512:
		switch pub := pubKey.(type) {
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pub, digest, signature) {
				return nil
			} else {
				return fmt.Errorf("this message was not signed with the private key")
			}
		default:
			return fmt.Errorf("invalid public key type for ECDSA signature scheme")
		}
	}

	return fmt.Errorf("invalid algorithm")
}
