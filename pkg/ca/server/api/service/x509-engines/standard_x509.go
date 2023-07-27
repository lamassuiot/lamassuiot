package x509engines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"hash"
	"math/big"
	"strings"
	"time"

	caerrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	cryptoengines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
)

type StandardX509Engine struct {
	cryptoEngine cryptoengines.CryptoEngine
	ocspURL      string
}

func NewStandardx509Engine(cryptoEngine cryptoengines.CryptoEngine, ocspURL string) X509Engine {
	return StandardX509Engine{
		cryptoEngine: cryptoEngine,
		ocspURL:      ocspURL,
	}
}

func (s StandardX509Engine) GetEngineConfig() api.EngineProviderInfo {
	return s.cryptoEngine.GetEngineConfig()
}

func (s StandardX509Engine) ImportCA(input api.PrivateKey, caName string) error {
	err := s.cryptoEngine.ImportCAPrivateKey(input, caName)
	if err != nil {
		return err
	}
	return nil
}
func (s StandardX509Engine) CreateCA(input api.CreateCAInput) (*x509.Certificate, error) {
	var signer crypto.Signer
	var derBytes []byte
	var err error

	if api.KeyType(input.KeyMetadata.KeyType) == api.RSA {
		signer, err = s.cryptoEngine.CreateRSAPrivateKey(input.KeyMetadata.KeyBits, input.Subject.CommonName)
		if err != nil {
			return nil, err
		}
	} else {
		var curve elliptic.Curve
		switch input.KeyMetadata.KeyBits {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsuported key size for ECDSA key")
		}
		signer, err = s.cryptoEngine.CreateECDSAPrivateKey(curve, input.Subject.CommonName)
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	templateCA := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:         input.Subject.CommonName,
			Country:            []string{input.Subject.Country},
			Province:           []string{input.Subject.State},
			Locality:           []string{input.Subject.Locality},
			Organization:       []string{input.Subject.Organization},
			OrganizationalUnit: []string{input.Subject.OrganizationUnit},
		},
		OCSPServer:            []string{s.ocspURL},
		NotBefore:             now,
		NotAfter:              input.CAExpiration.UTC(),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if api.KeyType(input.KeyMetadata.KeyType) == api.RSA {
		rsaPub := signer.Public().(*rsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, &templateCA, &templateCA, rsaPub, signer)
		if err != nil {
			return nil, err
		}
	} else {
		ecdsaPub := signer.Public().(*ecdsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, &templateCA, &templateCA, ecdsaPub, signer)
		if err != nil {
			return nil, err
		}
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (s StandardX509Engine) SignCertificateRequest(caCertificate *x509.Certificate, certificateExpiration time.Time, input *api.SignCertificateRequestInput) (*x509.Certificate, error) {
	privkey, err := s.cryptoEngine.GetPrivateKeyByID(input.CAName)
	if err != nil {
		return nil, err
	}

	var subject pkix.Name
	if input.SignVerbatim {
		subject = input.CertificateSigningRequest.Subject
	} else {
		subject = pkix.Name{
			CommonName: input.CommonName,
		}
	}

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	now := time.Now()

	certificateTemplate := x509.Certificate{
		PublicKeyAlgorithm: input.CertificateSigningRequest.PublicKeyAlgorithm,
		PublicKey:          input.CertificateSigningRequest.PublicKey,
		SerialNumber:       sn,
		Issuer:             caCertificate.Subject,
		Subject:            subject,
		NotBefore:          now,
		NotAfter:           certificateExpiration,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:           input.CertificateSigningRequest.DNSNames,
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, caCertificate, input.CertificateSigningRequest.PublicKey, privkey)
	if err != nil {
		return nil, &caerrors.GenericError{
			StatusCode: 400,
			Message:    err.Error(),
		}
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func (s StandardX509Engine) Sign(ca api.Certificate, message []byte, messageType string, signing_algorithm string) ([]byte, error) {
	privkey, err := s.cryptoEngine.GetPrivateKeyByID(ca.CAName)
	if err != nil {
		return nil, err
	}
	if ca.KeyMetadata.KeyType == api.ECDSA {
		var hasher []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signing_algorithm == "ECDSA_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signing_algorithm == "ECDSA_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signing_algorithm == "ECDSA_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {
			return nil, &caerrors.GenericError{
				StatusCode: 404,
				Message:    "Signing Algorithm not supported",
			}
		}
		if messageType == "RAW" {
			h.Write(message)
			hasher = h.Sum(nil)

		} else {
			hasher, err = hex.DecodeString(string(message))
			if err != nil {
				return nil, err
			}
		}
		signature, err := privkey.Sign(rand.Reader, hasher, hashFunc)
		if err != nil {
			return nil, &caerrors.GenericError{
				StatusCode: 400,
				Message:    "Inconsistency between hashed message and signature algorithm",
			}
		}
		return signature, nil
	} else {
		var hasher []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signing_algorithm == "RSASSA_PSS_SHA_256" || signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signing_algorithm == "RSASSA_PSS_SHA_384" || signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signing_algorithm == "RSASSA_PSS_SHA_512" || signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {
			return nil, &caerrors.GenericError{
				StatusCode: 404,
				Message:    "Signing Algorithm not supported",
			}
		}
		if messageType == "RAW" {
			h.Write(message)
			hasher = h.Sum(nil)
		} else {
			hasher, err = hex.DecodeString(string(message))
			if err != nil {
				return nil, err
			}
		}

		sigAlg := strings.Split(signing_algorithm, "_")
		if sigAlg[1] == "PSS" {
			var saltLength int
			switch hashFunc {
			case crypto.SHA256:
				saltLength = 32
			case crypto.SHA384:
				saltLength = 48
			case crypto.SHA512:
				saltLength = 64
			}
			signature, err := privkey.Sign(rand.Reader, hasher, &rsa.PSSOptions{
				SaltLength: saltLength,
				Hash:       hashFunc,
			})
			if err != nil {
				return nil, &caerrors.GenericError{
					StatusCode: 400,
					Message:    "Inconsistency between hashed message and signature algorithm",
				}
			}
			return signature, nil
		} else {
			signature, err := privkey.Sign(rand.Reader, hasher, hashFunc)
			if err != nil {
				return nil, err
			}
			return signature, nil
		}
	}
}

func (s StandardX509Engine) Verify(ca api.Certificate, signature []byte, message []byte, messageType string, signing_algorithm string) (bool, error) {
	var err error
	if ca.KeyMetadata.KeyType == api.ECDSA {
		var hasher []byte
		var h hash.Hash
		if signing_algorithm == "ECDSA_SHA_256" {
			h = sha256.New()
		} else if signing_algorithm == "ECDSA_SHA_384" {
			h = sha512.New384()
		} else if signing_algorithm == "ECDSA_SHA_512" {
			h = sha512.New()
		} else {
			return false, errors.New("Signing Algorithm not supported")
		}
		if messageType == "RAW" {
			h.Write(message)
			hasher = h.Sum(nil)
		} else {
			hasher, err = hex.DecodeString(string(message))
			if err != nil {
				return false, err
			}
		}
		pubK := ca.Certificate.PublicKey
		ecdsaKey, _ := pubK.(*ecdsa.PublicKey)

		return ecdsa.VerifyASN1(ecdsaKey, hasher, signature), nil
	} else {
		var hasher []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signing_algorithm == "RSASSA_PSS_SHA_256" || signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signing_algorithm == "RSASSA_PSS_SHA_384" || signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signing_algorithm == "RSASSA_PSS_SHA_512" || signing_algorithm == "RSASSA_PKCS1_V1_5_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {

			return false, errors.New("Signing Algorithm not supported")
		}
		if messageType == "RAW" {
			h.Write(message)
			hasher = h.Sum(nil)
		} else {
			hasher, err = hex.DecodeString(string(message))
			if err != nil {
				return false, err
			}
		}

		pubK := ca.Certificate.PublicKey
		rsaKey, _ := pubK.(*rsa.PublicKey)

		sigAlg := strings.Split(signing_algorithm, "_")
		if sigAlg[1] == "PSS" {
			var saltLength int
			switch hashFunc {
			case crypto.SHA256:
				saltLength = 32
			case crypto.SHA384:
				saltLength = 48
			case crypto.SHA512:
				saltLength = 64
			}
			err = rsa.VerifyPSS(rsaKey, hashFunc, hasher, signature, &rsa.PSSOptions{
				SaltLength: saltLength,
				Hash:       hashFunc,
			})
			if err != nil {
				return false, err
			}
			return true, nil
		} else {
			err = rsa.VerifyPKCS1v15(rsaKey, hashFunc, hasher, signature)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	}
}
