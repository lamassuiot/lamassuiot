package helpers

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
)

func X509CertFingerprint(cert x509.Certificate) string {
	fingerprint := sha1.Sum(cert.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}

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
