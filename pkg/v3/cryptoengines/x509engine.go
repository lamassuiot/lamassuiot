package cryptoengines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	log "github.com/sirupsen/logrus"
)

type X509EngineProvider struct {
	cryptoEngine CryptoEngine
	ocspURL      string
}

type X509Engine interface {
	GetEngineConfig() models.CryptoEngineProvider
	GetCACryptoSigner(caCertificate *x509.Certificate) (crypto.Signer, error)
	CreateRootCA(keyMetadata models.KeyMetadata, subject models.Subject, expirationTine time.Time) (*x509.Certificate, error)
	CreateSubordinateCA(parentCACertificate *x509.Certificate, parentCASigner crypto.Signer, keyMetadata models.KeyMetadata, subject models.Subject, expirationTine time.Time) (*x509.Certificate, error)
	SignCertificateRequest(caCertificate *x509.Certificate, csr *x509.CertificateRequest, expiration time.Time) (*x509.Certificate, error)
}

func NewX509Engine(cryptoEngine CryptoEngine, ocspURL string) X509Engine {
	return &X509EngineProvider{
		cryptoEngine: cryptoEngine,
		ocspURL:      ocspURL,
	}
}

func (s X509EngineProvider) GetEngineConfig() models.CryptoEngineProvider {
	return s.cryptoEngine.GetEngineConfig()
}

func (s X509EngineProvider) GetCACryptoSigner(caCertificate *x509.Certificate) (crypto.Signer, error) {
	caSn := helpers.SerialNumberToString(caCertificate.SerialNumber)
	return s.cryptoEngine.GetPrivateKeyByID(caSn)
}

func (s X509EngineProvider) CreateRootCA(keyMetadata models.KeyMetadata, subject models.Subject, expirationTine time.Time) (*x509.Certificate, error) {
	log.Debugf("[cryptoengine] starting root CA generation with key metadata [%v], subject [%v] and expiration time [%s]", keyMetadata, subject, expirationTine)
	templateCA, signer, err := s.genCertTemplateAndPrivateKey(keyMetadata, subject, expirationTine)
	if err != nil {
		log.Errorf("[cryptoengine] could not generate root CA: %s", err)
		return nil, err
	}

	log.Debugf("[cryptoengine] public-private key successfully generated")

	templateCA.IsCA = true

	var derBytes []byte
	if models.KeyType(keyMetadata.Type) == models.KeyType(x509.RSA) {
		rsaPub := signer.Public().(*rsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, templateCA, templateCA, rsaPub, signer)
		if err != nil {
			log.Errorf("[cryptoengine] could not sign root CA: %s", err)
			return nil, err
		}
	} else {
		ecdsaPub := signer.Public().(*ecdsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, templateCA, templateCA, ecdsaPub, signer)
		if err != nil {
			log.Errorf("[cryptoengine] could not sign root CA: %s", err)
			return nil, err
		}
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Errorf("[cryptoengine] could not parse root CA: %s", err)
		return nil, err
	}

	log.Debugf("[cryptoengine] root CA successfully generated with serial number [%s]", helpers.SerialNumberToString(cert.SerialNumber))
	return cert, nil
}

func (s X509EngineProvider) CreateSubordinateCA(parentCACertificate *x509.Certificate, parentCASigner crypto.Signer, keyMetadata models.KeyMetadata, subject models.Subject, expirationTine time.Time) (*x509.Certificate, error) {
	templateCA, signer, err := s.genCertTemplateAndPrivateKey(keyMetadata, subject, expirationTine)
	if err != nil {
		return nil, err
	}

	var pubKey interface{}
	if models.KeyType(keyMetadata.Type) == models.KeyType(x509.RSA) {
		pubKey = signer.Public().(*rsa.PublicKey)
	} else {
		pubKey = signer.Public().(*ecdsa.PublicKey)
	}

	templateCA.IsCA = true
	certificateBytes, err := x509.CreateCertificate(rand.Reader, templateCA, parentCACertificate, pubKey, parentCASigner)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, err
	}

	return certificate, nil

}

func (s X509EngineProvider) SignCertificateRequest(caCertificate *x509.Certificate, csr *x509.CertificateRequest, expirationDate time.Time) (*x509.Certificate, error) {
	log.Debugf("[cryptoengine] starting csr signing with CA [%s]", caCertificate.Subject.CommonName)
	log.Debugf("[cryptoengine] csr cn is [%s]", csr.Subject.CommonName)
	caSn := helpers.SerialNumberToString(caCertificate.SerialNumber)

	log.Debugf("[cryptoengine] requesting CA signer object to cryptoengine instance")
	privkey, err := s.cryptoEngine.GetPrivateKeyByID(caSn)
	if err != nil {
		return nil, err
	}
	log.Debugf("[cryptoengine] successfully retrieved CA signer object")

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	now := time.Now()

	certificateTemplate := x509.Certificate{
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: sn,
		Issuer:       caCertificate.Subject,
		Subject:      csr.Subject,
		NotBefore:    now,
		NotAfter:     expirationDate,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, caCertificate, csr.PublicKey, privkey)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func (s X509EngineProvider) genCertTemplateAndPrivateKey(keyMetadata models.KeyMetadata, subject models.Subject, expirationTine time.Time) (*x509.Certificate, crypto.Signer, error) {
	var err error
	var signer crypto.Signer

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	log.Debugf("[cryptoengine] generates serial number for root CA is [%s]", helpers.SerialNumberToString(sn))

	if models.KeyType(keyMetadata.Type) == models.KeyType(x509.RSA) {
		log.Debugf("[cryptoengine] requesting cryptoengine instance for RSA key generation")
		signer, err = s.cryptoEngine.CreateRSAPrivateKey(keyMetadata.Bits, helpers.SerialNumberToString(sn))
		if err != nil {
			log.Errorf("[cryptoengine] cryptoengine instance failed while generating RSA key: %s", err)
			return nil, nil, err
		}
		log.Debugf("[cryptoengine] cryptoengine successfully generated RSA key")
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
			return nil, nil, errors.New("unsuported key size for ECDSA key")
		}
		log.Debugf("[cryptoengine] requesting cryptoengine instance for ECDSA key generation")
		signer, err = s.cryptoEngine.CreateECDSAPrivateKey(curve, helpers.SerialNumberToString(sn))
		if err != nil {
			log.Errorf("[cryptoengine] cryptoengine instance failed while generating ECDSA key: %s", err)
			return nil, nil, err
		}
		log.Debugf("[cryptoengine] cryptoengine successfully generated ECDSA key")
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
		OCSPServer:            []string{s.ocspURL},
		NotBefore:             now,
		NotAfter:              expirationTine,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return &template, signer, nil
}
