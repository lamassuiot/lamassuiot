package helpers

import (
	"context"
	"crypto/x509"

	corehelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/sirupsen/logrus"
)

func FormatHexWithColons(data []byte) string {
	return corehelpers.FormatHexWithColons(data)
}

// GetSubjectKeyID returns the Subject Key Identifier (SKI) of the given x509 certificate.
// If the SKI is not present in the certificate, it generates one from the public key.
func GetSubjectKeyID(ctx context.Context, logger *logrus.Entry, x509Cert *x509.Certificate) (string, error) {
	return corehelpers.GetSubjectKeyID(ctx, logger, x509Cert)
}
