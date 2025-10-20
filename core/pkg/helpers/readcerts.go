package helpers

import (
	"cloudflare/circl/sign/mldsa/mldsa44"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"cloudflare/circl/sign/mldsa/mldsa87"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

func ReadCertificateFromFile(filePath string) (*x509.Certificate, error) {
	if filePath == "" {
		return nil, fmt.Errorf("cannot open empty filepath")
	}

	certFileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return ParseCertificate(string(certFileBytes))
}

func ParseCertificate(cert string) (*x509.Certificate, error) {
	certDERBlock, _ := pem.Decode([]byte(cert))
	return x509.ParseCertificate(certDERBlock.Bytes)
}

func ParseCertificateRequest(cert string) (*x509.CertificateRequest, error) {
	certDERBlock, _ := pem.Decode([]byte(cert))
	return x509.ParseCertificateRequest(certDERBlock.Bytes)
}

func ReadPrivateKeyFromFile(filePath string) (interface{}, error) {
	keyFileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKey(keyFileBytes)
}

func ParsePrivateKey(privKeyBytes []byte) (interface{}, error) {
	keyDERBlock, _ := pem.Decode(privKeyBytes)

	if key, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, *mldsa44.PrivateKey, *mldsa65.PrivateKey, *mldsa87.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

func CertificateToPEM(c *x509.Certificate) string {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	return string(pemCert)
}

func PrivateKeyToPEM(key any) (string, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		},
	)

	return string(pemdata), nil
}

func GenerateSelfSignedCertificate(key crypto.Signer, cn string) (*x509.Certificate, error) {
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	crt := x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn},
	}

	crtB, _ := x509.CreateCertificate(rand.Reader, &crt, &crt, key.Public(), key)
	crtP, err := x509.ParseCertificate(crtB)

	return crtP, err
}
