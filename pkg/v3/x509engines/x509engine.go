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
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

var lCEngine *logrus.Entry = logrus.WithField("", "")

func SetCryptoEngineLogger(lgr *logrus.Entry) {
	lCEngine = lgr
}

type X509Engine struct {
	cryptoEngine           cryptoengines.CryptoEngine
	validationAuthorityURL string
}

func NewX509Engine(cryptoEngine *cryptoengines.CryptoEngine, validationAuthorityURL string) X509Engine {
	return X509Engine{
		cryptoEngine:           *cryptoEngine,
		validationAuthorityURL: validationAuthorityURL,
	}
}

func (engine X509Engine) GetEngineConfig() models.CryptoEngineInfo {
	return engine.cryptoEngine.GetEngineConfig()
}

func (engine X509Engine) GetCACryptoSigner(caCertificate *x509.Certificate) (crypto.Signer, error) {
	caSn := helpers.SerialNumberToString(caCertificate.SerialNumber)
	return engine.cryptoEngine.GetPrivateKeyByID(caSn)
}

func (engine X509Engine) CreateRootCA(caID string, keyMetadata models.KeyMetadata, subject models.Subject, expirationTine time.Time) (*x509.Certificate, error) {
	lCEngine.Debugf("starting root CA generation with key metadata [%v], subject [%v] and expiration time [%s]", keyMetadata, subject, expirationTine)
	templateCA, signer, err := engine.genCertTemplateAndPrivateKey(keyMetadata, subject, expirationTine, caID, caID)
	if err != nil {
		lCEngine.Errorf("could not generate root CA Template and Key: %s", err)
		return nil, err
	}

	lCEngine.Debugf("public-private key successfully generated")

	templateCA.IsCA = true

	var derBytes []byte
	if models.KeyType(keyMetadata.Type) == models.KeyType(x509.RSA) {
		rsaPub := signer.Public().(*rsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, templateCA, templateCA, rsaPub, signer)
		if err != nil {
			lCEngine.Errorf("could not sign root CA: %s", err)
			return nil, err
		}
	} else {
		ecdsaPub := signer.Public().(*ecdsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, templateCA, templateCA, ecdsaPub, signer)
		if err != nil {
			lCEngine.Errorf("could not sign root CA: %s", err)
			return nil, err
		}
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		lCEngine.Errorf("could not parse root CA: %s", err)
		return nil, err
	}

	lCEngine.Debugf("root CA successfully generated with serial number [%s]", helpers.SerialNumberToString(cert.SerialNumber))
	return cert, nil
}

func (engine X509Engine) CreateSubordinateCA(aki string, caID string, parentCACertificate *x509.Certificate, keyMetadata models.KeyMetadata, subject models.Subject, expirationTine time.Time, parentEngine X509Engine) (*x509.Certificate, error) {
	templateCA, signer, err := engine.genCertTemplateAndPrivateKey(keyMetadata, subject, expirationTine, aki, caID)
	if err != nil {
		lCEngine.Errorf("could not generate subordinate CA Template and Key: %s", err)
		return nil, err
	}

	var pubKey interface{}
	if models.KeyType(keyMetadata.Type) == models.KeyType(x509.RSA) {
		pubKey = signer.Public().(*rsa.PublicKey)
	} else {
		pubKey = signer.Public().(*ecdsa.PublicKey)
	}

	parentSN := helpers.SerialNumberToString(parentCACertificate.SerialNumber)
	parentCASigner, err := parentEngine.cryptoEngine.GetPrivateKeyByID(CryptoAssetLRI(CertificateAuthority, parentSN))
	if err != nil {
		lCEngine.Errorf("could not get parent signer key '%s': %s", parentSN, err)
		return nil, err
	}

	templateCA.IsCA = true
	certificateBytes, err := x509.CreateCertificate(rand.Reader, templateCA, parentCACertificate, pubKey, parentCASigner)
	if err != nil {
		lCEngine.Errorf("could not sign subordinate CA: %s", err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		lCEngine.Errorf("could not parse subordinate CA: %s", err)
		return nil, err
	}

	return certificate, nil
}

func (engine X509Engine) SignCertificateRequest(caCertificate *x509.Certificate, csr *x509.CertificateRequest, expirationDate time.Time) (*x509.Certificate, error) {
	lCEngine.Debugf("starting csr signing with CA [%s]", caCertificate.Subject.CommonName)
	lCEngine.Debugf("csr cn is [%s]", csr.Subject.CommonName)
	caSn := helpers.SerialNumberToString(caCertificate.SerialNumber)

	lCEngine.Debugf("requesting CA signer object to crypto engine instance")
	privkey, err := engine.cryptoEngine.GetPrivateKeyByID(CryptoAssetLRI(CertificateAuthority, caSn))
	if err != nil {
		return nil, err
	}
	lCEngine.Debugf("successfully retrieved CA signer object")

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	now := time.Now()

	certificateTemplate := x509.Certificate{
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		AuthorityKeyId:     caCertificate.SubjectKeyId,
		SerialNumber:       sn,
		Issuer:             caCertificate.Subject,
		Subject:            csr.Subject,
		NotBefore:          now,
		NotAfter:           expirationDate,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, caCertificate, csr.PublicKey, privkey)
	if err != nil {
		lCEngine.Errorf("could not sign certificate: %s", err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		lCEngine.Errorf("could not parse signed certificate %s", err)
		return nil, err
	}

	return certificate, nil
}

func (engine X509Engine) genCertTemplateAndPrivateKey(keyMetadata models.KeyMetadata, subject models.Subject, expirationTine time.Time, aki, ski string) (*x509.Certificate, crypto.Signer, error) {
	var err error
	var signer crypto.Signer

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	lCEngine.Debugf("generates serial number for root CA is [%s]", helpers.SerialNumberToString(sn))
	lri := CryptoAssetLRI(CertificateAuthority, helpers.SerialNumberToString(sn))

	if models.KeyType(keyMetadata.Type) == models.KeyType(x509.RSA) {
		lCEngine.Debugf("requesting cryptoengine instance for RSA key generation: %s", lri)

		signer, err = engine.cryptoEngine.CreateRSAPrivateKey(keyMetadata.Bits, lri)
		if err != nil {
			lCEngine.Errorf("cryptoengine instance failed while generating RSA key: %s", err)
			return nil, nil, err
		}
		lCEngine.Debugf("cryptoengine successfully generated RSA key")
	} else {
		var curve elliptic.Curve
		switch keyMetadata.Bits {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, nil, errors.New("unsupported key size for ECDSA key")
		}

		lCEngine.Debugf("requesting cryptoengine instance for ECDSA key generation: %s", lri)
		signer, err = engine.cryptoEngine.CreateECDSAPrivateKey(curve, lri)
		if err != nil {
			lCEngine.Errorf("cryptoengine instance failed while generating ECDSA key: %s", err)
			return nil, nil, err
		}
		lCEngine.Debugf("cryptoengine successfully generated ECDSA key")
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:         subject.CommonName,
			Country:            []string{subject.Country},
			Province:           []string{subject.State},
			Locality:           []string{subject.Locality},
			Organization:       []string{subject.Organization},
			OrganizationalUnit: []string{subject.OrganizationUnit},
		},
		AuthorityKeyId: []byte(aki),
		SubjectKeyId:   []byte(ski),
		OCSPServer: []string{
			fmt.Sprintf("%s/ocsp", engine.validationAuthorityURL),
		},
		CRLDistributionPoints: []string{
			fmt.Sprintf("%s/crl/%s", engine.validationAuthorityURL, ski),
		},
		NotBefore:             now,
		NotAfter:              expirationTine,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsage(x509.ExtKeyUsageOCSPSigning),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return &template, signer, nil
}

func (engine X509Engine) Sign(cAssetType CryptoAssetType, certificate *x509.Certificate, message []byte, messageType models.SignMessageType, signingAlgorithm string) ([]byte, error) {
	lCEngine.Debugf("starting standard signing with certificate [%s]", certificate.Subject.CommonName)
	sn := helpers.SerialNumberToString(certificate.SerialNumber)

	lCEngine.Debugf("requesting signer object to crypto engine instance")
	privkey, err := engine.cryptoEngine.GetPrivateKeyByID(CryptoAssetLRI(cAssetType, sn))
	if err != nil {
		return nil, err
	}
	lCEngine.Debugf("successfully retrieved certificate signer object")

	if certificate.PublicKeyAlgorithm == x509.ECDSA {
		var digest []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signingAlgorithm == "ECDSA_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signingAlgorithm == "ECDSA_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signingAlgorithm == "ECDSA_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {
			return nil, errs.ErrEngineAlgNotSupported
		}
		if messageType == models.Raw {
			h.Write(message)
			digest = h.Sum(nil)

		} else {
			digest = message
			if err != nil {
				return nil, err
			}
		}
		signature, err := privkey.Sign(rand.Reader, digest, hashFunc)
		if err != nil {
			return nil, err
		}
		return signature, nil
	} else if certificate.PublicKeyAlgorithm == x509.RSA {
		var digest []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signingAlgorithm == "RSASSA_PSS_SHA_256" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signingAlgorithm == "RSASSA_PSS_SHA_384" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signingAlgorithm == "RSASSA_PSS_SHA_512" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {
			return nil, errs.ErrEngineAlgNotSupported
		}
		if messageType == models.Raw {
			h.Write(message)
			digest = h.Sum(nil)
		} else {
			digest = message
			if err != nil {
				return nil, err
			}
		}

		sigAlg := strings.Split(signingAlgorithm, "_")
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
			signature, err := privkey.Sign(rand.Reader, digest, &rsa.PSSOptions{
				SaltLength: saltLength,
				Hash:       hashFunc,
			})
			if err != nil {
				return nil, errs.ErrEngineHashAlgInconsistency
			}
			return signature, nil
		} else {
			signature, err := privkey.Sign(rand.Reader, digest, hashFunc)
			if err != nil {
				return nil, err
			}
			return signature, nil
		}
	} else {
		return nil, fmt.Errorf("certificate has unsupported public key algorithm: %s", certificate.PublicKeyAlgorithm)
	}
}

func (engine X509Engine) Verify(caCertificate *x509.Certificate, signature []byte, message []byte, messageType models.SignMessageType, signingAlgorithm string) (bool, error) {
	var err error
	if caCertificate.PublicKeyAlgorithm == x509.ECDSA {
		var hasher []byte
		var h hash.Hash
		if signingAlgorithm == "ECDSA_SHA_256" {
			h = sha256.New()
		} else if signingAlgorithm == "ECDSA_SHA_384" {
			h = sha512.New384()
		} else if signingAlgorithm == "ECDSA_SHA_512" {
			h = sha512.New()
		} else {
			return false, errs.ErrEngineAlgNotSupported
		}

		if messageType == models.Raw {
			h.Write(message)
			hasher = h.Sum(nil)
		} else {
			hasher, err = hex.DecodeString(string(message))
			if err != nil {
				return false, err
			}
		}
		pubK := caCertificate.PublicKey
		ecdsaKey, _ := pubK.(*ecdsa.PublicKey)

		return ecdsa.VerifyASN1(ecdsaKey, hasher, signature), nil
	} else if caCertificate.PublicKeyAlgorithm == x509.RSA {
		var hasher []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signingAlgorithm == "RSASSA_PSS_SHA_256" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signingAlgorithm == "RSASSA_PSS_SHA_384" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signingAlgorithm == "RSASSA_PSS_SHA_512" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {

			return false, errs.ErrEngineAlgNotSupported
		}

		if messageType == models.Raw {
			h.Write(message)
			hasher = h.Sum(nil)
		} else {
			hasher = message
			if err != nil {
				return false, err
			}
		}

		pubK := caCertificate.PublicKey
		rsaKey, _ := pubK.(*rsa.PublicKey)

		sigAlg := strings.Split(signingAlgorithm, "_")
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
	} else {
		return false, fmt.Errorf("CA has unsupported public key algorithm: %s", caCertificate.PublicKeyAlgorithm)
	}
}

type CryptoAssetType string

const (
	CertificateAuthority CryptoAssetType = "certauth"
	Certificate          CryptoAssetType = "cert"
)

func CryptoAssetLRI(cryptoAssetType CryptoAssetType, keyID string) string {
	return fmt.Sprintf("lms-caservice-%s-keyid-%s", cryptoAssetType, keyID)
}
