package clientcertificateextractor

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

const AwsALBClientCertificateHeader = "X-Amzn-Mtls-Clientcert"

type AwsALBClientCertificateExtractor struct {
	logger *logrus.Entry
}

func NewAwsALBClientCertificateExtractor(logger *logrus.Entry) AwsALBClientCertificateExtractor {
	return AwsALBClientCertificateExtractor{
		logger: logger.WithField("extractor", "aws-alb-client-certificate"),
	}
}

func (extractor AwsALBClientCertificateExtractor) ExtractCertificate(headers http.Header) []*x509.Certificate {
	cert := headers.Get(AwsALBClientCertificateHeader)
	if cert == "" {
		return []*x509.Certificate{}
	}

	decodedCert, _ := url.QueryUnescape(strings.ReplaceAll(cert, "+", "%2B"))

	var certs []*x509.Certificate
	rest := []byte(decodedCert)

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			extractor.logger.Warnf("request includes header %s but could not decode certificate. Skipping: %s", AwsALBClientCertificateHeader, err)
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}
