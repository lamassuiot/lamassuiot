package x509engine

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

	"github.com/lamassuiot/lamassuiot/internal/ca/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
)

type X509EngineProvider struct {
	cryptoEngine cryptoengines.CryptoEngine
	ocspURL      string
}

type X509Engine interface {
	GetEngineConfig() models.CryptoEngineProvider
	GetCACryptoSigner(caCertificate *x509.Certificate) (crypto.Signer, error)
	CreateRootCA(keyMetadata models.KeyMetadata, subject models.Subject, duration time.Duration) (*x509.Certificate, error)
	CreateSubordinateCA(parentCACertificate *x509.Certificate, parentCASigner crypto.Signer, keyMetadata models.KeyMetadata, subject models.Subject, duration time.Duration) (*x509.Certificate, error)
	SignCertificateRequest(caCertificate *x509.Certificate, csr *x509.CertificateRequest, issuanceDuration time.Duration, signVerbatim bool, subject models.Subject) (*x509.Certificate, error)
}

func NewX509Engine(cryptoEngine cryptoengines.CryptoEngine, ocspURL string) X509Engine {
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

func (s X509EngineProvider) CreateRootCA(keyMetadata models.KeyMetadata, subject models.Subject, duration time.Duration) (*x509.Certificate, error) {
	templateCA, signer, err := s.genCertTemplateAndPrivateKey(keyMetadata, subject, duration)
	if err != nil {
		return nil, err
	}

	templateCA.IsCA = true

	var derBytes []byte
	if models.KeyType(keyMetadata.Type) == models.KeyType(x509.RSA) {
		rsaPub := signer.Public().(*rsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, templateCA, templateCA, rsaPub, signer)
		if err != nil {
			return nil, err
		}
	} else {
		ecdsaPub := signer.Public().(*ecdsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, templateCA, templateCA, ecdsaPub, signer)
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

func (s X509EngineProvider) CreateSubordinateCA(parentCACertificate *x509.Certificate, parentCASigner crypto.Signer, keyMetadata models.KeyMetadata, subject models.Subject, duration time.Duration) (*x509.Certificate, error) {
	templateCA, signer, err := s.genCertTemplateAndPrivateKey(keyMetadata, subject, duration)
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

func (s X509EngineProvider) SignCertificateRequest(caCertificate *x509.Certificate, csr *x509.CertificateRequest, issuanceDuration time.Duration, signVerbatim bool, subject models.Subject) (*x509.Certificate, error) {
	caSn := helpers.SerialNumberToString(caCertificate.SerialNumber)

	privkey, err := s.cryptoEngine.GetPrivateKeyByID(caSn)
	if err != nil {
		return nil, err
	}

	var certSubject pkix.Name
	if signVerbatim {
		certSubject = csr.Subject
	} else {
		certSubject = pkix.Name{
			CommonName:         subject.CommonName,
			Country:            []string{subject.Country},
			Province:           []string{subject.State},
			Locality:           []string{subject.Locality},
			Organization:       []string{subject.Organization},
			OrganizationalUnit: []string{subject.OrganizationUnit},
		}
	}

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	now := time.Now()

	certificateTemplate := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: sn,
		Issuer:       caCertificate.Subject,
		Subject:      certSubject,
		NotBefore:    now,
		NotAfter:     now.Add(issuanceDuration),
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

func (s X509EngineProvider) genCertTemplateAndPrivateKey(keyMetadata models.KeyMetadata, subject models.Subject, duration time.Duration) (*x509.Certificate, crypto.Signer, error) {
	var err error
	var signer crypto.Signer

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	if models.KeyType(keyMetadata.Type) == models.KeyType(x509.RSA) {
		signer, err = s.cryptoEngine.CreateRSAPrivateKey(keyMetadata.Bits, helpers.SerialNumberToString(sn))
		if err != nil {
			return nil, nil, err
		}
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
		signer, err = s.cryptoEngine.CreateECDSAPrivateKey(curve, helpers.SerialNumberToString(sn))
		if err != nil {
			return nil, nil, err
		}
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
		NotAfter:              now.Add(duration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return &template, signer, nil
}
