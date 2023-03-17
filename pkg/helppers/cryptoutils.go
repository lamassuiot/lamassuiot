package helppers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/pkg/models"
	log "github.com/sirupsen/logrus"
)

func GenerateCertificateRequest(subject models.Subject, key *rsa.PrivateKey) (*x509.CertificateRequest, error) {

	template := x509.CertificateRequest{
		Subject: SubjectToPkixName(subject),
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return csr, err
}

func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return privkey, nil
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func LoadSytemCACertPool() *x509.CertPool {
	certPool := x509.NewCertPool()
	systemCertPool, err := x509.SystemCertPool()
	if err == nil {
		certPool = systemCertPool
	} else {
		log.Warnf("could not get system cert pool (trusted CAs). Using empty pool: %s", err)
	}

	return certPool
}

func LoadSytemCACertPoolWithExtraCAsFromFiles(casToAdd []string) *x509.CertPool {
	certPool := x509.NewCertPool()
	systemCertPool, err := x509.SystemCertPool()
	if err == nil {
		certPool = systemCertPool
	} else {
		log.Warnf("could not get system cert pool (trusted CAs). Using empty pool: %s", err)
	}

	for _, ca := range casToAdd {
		if ca == "" {
			continue
		}

		caCert, err := ReadCertificateFromFile(ca)
		if err != nil {
			log.Warnf("could not load CA certificate in %s. Skipping CA: %s", ca, err)
			continue
		}

		certPool.AddCert(caCert)
	}

	return certPool
}
