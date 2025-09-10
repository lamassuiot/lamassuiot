package helpers

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

func FormatHexWithColons(data []byte) string {
	hexParts := make([]string, len(data))
	for i, b := range data {
		hexParts[i] = fmt.Sprintf("%02X", b) // Format each byte as uppercase hex
	}
	return strings.Join(hexParts, ":") // Join with colons
}

// GetSubjectKeyID returns the Subject Key Identifier (SKID) of the given x509 certificate.
// If the SKID is not present in the certificate, it generates one from the public key.
func GetSubjectKeyID(logger *logrus.Entry, x509Cert *x509.Certificate) (string, error) {
	certSkid := x509Cert.SubjectKeyId
	if len(certSkid) > 0 {
		return hex.EncodeToString(certSkid), nil
	} else {
		logger.Debugf("certificate %s does not have a Subject Key Identifier. Generating one from the public key", x509Cert.Subject.CommonName)
		skid, err := software.NewSoftwareCryptoEngine(logger).EncodePKIXPublicKeyDigest(x509Cert.PublicKey)
		if err != nil {
			logger.Errorf("could not encode public key digest for certificate %s: %s", x509Cert.Subject.CommonName, err)
			return "", err
		}
		return skid, nil
	}
}
