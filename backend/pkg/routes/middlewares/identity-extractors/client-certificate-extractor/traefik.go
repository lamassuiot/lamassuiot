package clientcertificateextractor

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

const traefikClientCertificateHeader = "X-Forwarded-Tls-Client-Cert"

type traefikClientCertificateExtractor struct {
	logger *logrus.Entry
}

func NewTraefikClientCertificateExtractor(logger *logrus.Entry) traefikClientCertificateExtractor {
	return traefikClientCertificateExtractor{
		logger: logger.WithField("extractor", "traefik-client-certificate"),
	}
}

// ExtractCertificate parses the X-Forwarded-Tls-Client-Cert header set by Traefik's
// passTLSClientCert middleware. Each certificate is PEM-encoded with the delimiters
// and newlines stripped, and when a chain is present its certificates are comma-separated.
func (extractor traefikClientCertificateExtractor) ExtractCertificate(headers http.Header) []*x509.Certificate {
	header := headers.Get(traefikClientCertificateHeader)
	if header == "" {
		return []*x509.Certificate{}
	}

	var certs []*x509.Certificate
	for _, encodedCert := range strings.Split(header, ",") {
		derBytes, err := base64.StdEncoding.DecodeString(encodedCert)
		if err != nil {
			extractor.logger.Warnf("request includes header %s but could not decode certificate. Skipping: %s", traefikClientCertificateHeader, err)
			continue
		}

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			extractor.logger.Warnf("request includes header %s but could not parse certificate. Skipping: %s", traefikClientCertificateHeader, err)
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}
