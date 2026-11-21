package helpers

import (
	"crypto/x509"
	"fmt"
	"time"
)

func ValidateCertificate(ca, cert *x509.Certificate, considerExpiration bool) error {
	_, err := ValidateCertificates(ca, []*x509.Certificate{cert}, considerExpiration)
	return err
}

// ValidateCertificates verifies that certs[0] chains up to ca, using the rest of certs as intermediates. It returns
// the verified chain: certs[0] first and ca last. Certificates of certs that are not part of it are left out.
func ValidateCertificates(ca *x509.Certificate, certs []*x509.Certificate, considerExpiration bool) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided for validation")
	}

	leafCert := certs[0]

	// Always reject future-dated certificates.
	if time.Now().Before(leafCert.NotBefore) {
		return nil, fmt.Errorf("certificate is not yet valid (NotBefore=%s)", leafCert.NotBefore.UTC().Format(time.RFC3339))
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if !considerExpiration {
		opts.CurrentTime = leafCert.NotBefore //set to same date as certificate, otherwise expired certificates will trigger Verify error
	}

	//add all but the leaf certificate to the intermediates pool
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediatePool.AddCert(certs[i])
	}

	opts.Intermediates = intermediatePool

	chains, err := leafCert.Verify(opts)
	if err != nil {
		return nil, err
	}

	return chains[0], nil
}
