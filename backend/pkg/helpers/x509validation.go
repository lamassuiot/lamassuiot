package helpers

import (
	"crypto/x509"
)

func ValidateCertificate(ca, cert *x509.Certificate, considerExpiration bool) error {
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if !considerExpiration {
		opts.CurrentTime = cert.NotBefore //set to same date as certificate, otherwise expired certificates will trigger Verify error
	}
	_, err := cert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}
