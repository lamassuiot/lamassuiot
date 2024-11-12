package clientcertificateextractor

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
)

const nginxClientCertificateHeader = "ssl-client-cert"

type nginxClientCertificateExtractor struct {
	logger *logrus.Entry
}

func NewNginxClientCertificateExtractor(logger *logrus.Entry) nginxClientCertificateExtractor {
	return nginxClientCertificateExtractor{
		logger: logger.WithField("extractor", "nginx-client-certificate"),
	}
}

func (extractor nginxClientCertificateExtractor) ExtractCertificate(headers http.Header) []*x509.Certificate {
	cert := headers.Get(nginxClientCertificateHeader)
	if cert == "" {
		return []*x509.Certificate{}
	}

	decodedCert, _ := url.QueryUnescape(cert)
	block, _ := pem.Decode([]byte(decodedCert))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		extractor.logger.Warnf("request includes header %s but could not decode certificate. Skipping: %s", nginxClientCertificateHeader, err)
		return []*x509.Certificate{}
	}

	return []*x509.Certificate{certificate}
}
