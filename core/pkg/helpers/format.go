package helpers

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// FormatHexWithColons formats bytes as uppercase hexadecimal pairs separated by colons.
func FormatHexWithColons(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// GetSubjectKeyID returns the certificate SKI, or a SHA-256 digest of its PKIX public key.
func GetSubjectKeyID(_ context.Context, logger *logrus.Entry, cert *x509.Certificate) (string, error) {
	if len(cert.SubjectKeyId) > 0 {
		return hex.EncodeToString(cert.SubjectKeyId), nil
	}
	logger.Debugf("certificate %s does not have a Subject Key Identifier. Generating one from the public key", cert.Subject.CommonName)
	pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pub)
	return hex.EncodeToString(digest[:]), nil
}
