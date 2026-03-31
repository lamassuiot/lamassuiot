package helpers

import (
	"crypto/x509"
	"fmt"
)

func ValidateCertificate(ca, cert *x509.Certificate, considerExpiration bool) error {
	return ValidateCertificates(ca, []*x509.Certificate{cert}, considerExpiration)
}

func ValidateCertificates(ca *x509.Certificate, certs []*x509.Certificate, considerExpiration bool) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates provided for validation")
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	leafCert := certs[0]

	if !considerExpiration {
		opts.CurrentTime = leafCert.NotBefore //set to same date as certificate, otherwise expired certificates will trigger Verify error
	}

	//add all but the leaf certificate to the intermediates pool
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediatePool.AddCert(certs[i])
	}

	opts.Intermediates = intermediatePool

	_, err := leafCert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}
