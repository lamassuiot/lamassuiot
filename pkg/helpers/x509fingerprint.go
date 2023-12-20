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
