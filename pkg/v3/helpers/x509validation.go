package helpers

import (
	"crypto/x509"
)

func ValidateCertificate(ca *x509.Certificate, cert x509.Certificate) error {
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}
