package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/google/uuid"
	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	log "github.com/sirupsen/logrus"
)

//Cammbio de la función para definir la longevidad de la expiración de la CA.

func GenerateSelfSignedCA(keyType x509.PublicKeyAlgorithm, expirationTime time.Duration, commonName string) (*x509.Certificate, any, error) {
	var err error
	var key any
	var pubKey any

	switch keyType {
	case x509.RSA:
		rsaKey, err := GenerateRSAKey(2048)
		if err != nil {
			return nil, nil, err
		}
		key = rsaKey
		pubKey = &rsaKey.PublicKey
	case x509.ECDSA:
		eccKey, err := GenerateECDSAKey(elliptic.P224())
		if err != nil {
			return nil, nil, err
		}
		key = eccKey
		pubKey = &eccKey.PublicKey
	}

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	template := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              (time.Now().Add(expirationTime)),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsage(x509.ExtKeyUsageOCSPSigning),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte(uuid.NewString()),
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// defined to generate certificates with RSA and ECDSA keys
func GenerateCertificateRequest(subject cmodels.Subject, key any) (*x509.CertificateRequest, error) {
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

// defined to generate certificates with RSA and ECDSA keys
func GenerateCertificateRequestWithExtensions(subject cmodels.Subject, extensions []pkix.Extension, key any) (*x509.CertificateRequest, error) {
	template := x509.CertificateRequest{
		Subject:         SubjectToPkixName(subject),
		ExtraExtensions: extensions,
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

func GenerateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privkey, err := ecdsa.GenerateKey(curve, rand.Reader)

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

func LoadSystemCACertPoolWithExtraCAsFromFiles(casToAdd []string) *x509.CertPool {
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

func ValidateCertAndPrivKey(cert *x509.Certificate, rsaKey *rsa.PrivateKey, ecKey *ecdsa.PrivateKey) (bool, error) {
	errs := []string{
		"tls: private key type does not match public key type",
		"tls: private key does not match public key",
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if rsaKey != nil {
		keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		_, err := tls.X509KeyPair(pemCert, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}))
		if err == nil {
			return true, nil
		}

		contains := slices.Contains(errs, err.Error())
		if contains {
			return false, nil
		}

		return false, err
	}

	if ecKey != nil {
		keyBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return false, err
		}

		_, err = tls.X509KeyPair(pemCert, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
		if err == nil {
			return true, nil
		}

		contains := slices.Contains(errs, err.Error())
		if contains {
			return false, nil
		}

		return false, err
	}

	return false, fmt.Errorf("both keys are nil")
}

func CalculateRSAKeySizes(keyMin int, KeyMax int) []int {
	var keySizes []int
	key := keyMin
	for {
		if key%128 == 0 {
			keySizes = append(keySizes, key)
			key = key + 128
		}
		if key%1024 == 0 {
			break
		}
	}
	for {
		if key%1024 == 0 {
			keySizes = append(keySizes, key)
			if key == KeyMax {
				break
			}
			key = key + 1024
		} else {
			break
		}
	}
	return keySizes
}

func CalculateECDSAKeySizes(keyMin int, KeyMax int) []int {
	var keySizes []int
	keySizes = append(keySizes, keyMin)
	if keyMin < 224 && KeyMax > 224 {
		keySizes = append(keySizes, 224)
	}
	if keyMin < 256 && KeyMax > 256 {
		keySizes = append(keySizes, 256)
	}
	if keyMin < 384 && KeyMax > 384 {
		keySizes = append(keySizes, 384)
	}
	if keyMin < 521 && KeyMax >= 521 {
		keySizes = append(keySizes, 521)
	}
	return keySizes
}

func EqualPublicKeys(pubKey1, pubKey2 any) bool {
	switch pubKey1.(type) {
	case *rsa.PublicKey:
		pk2, ok := pubKey2.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return pubKey1.(*rsa.PublicKey).Equal(pk2)
	case *ecdsa.PublicKey:
		pk2, ok := pubKey2.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return pubKey1.(*ecdsa.PublicKey).Equal(pk2)
	}

	return false
}

func ComputePublicKeyFingerprint[T *x509.Certificate | *x509.CertificateRequest](cert T) string {
	switch v := any(cert).(type) {
	case *x509.Certificate:
		return PublicKeyFingerprint(v.PublicKey)
	case *x509.CertificateRequest:
		return PublicKeyFingerprint(v.PublicKey)
	default:
		return ""
	}
}

func PublicKeyFingerprint(pubKey any) string {
	pk, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(pk))
}
