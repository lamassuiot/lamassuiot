package clientcertificateextractor

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

const envoyClientCertificateHeader = "x-forwarded-client-cert"

type envoyClientCertificateExtractor struct {
	logger *logrus.Entry
}

func NewEnvoyClientCertificateExtractor(logger *logrus.Entry) envoyClientCertificateExtractor {
	return envoyClientCertificateExtractor{
		logger: logger.WithField("extractor", "envoy-client-certificate"),
	}
}

func (extractor envoyClientCertificateExtractor) ExtractCertificate(headers http.Header) []*x509.Certificate {
	forwardedClientCertificate := headers.Get(envoyClientCertificateHeader)
	if forwardedClientCertificate == "" {
		return []*x509.Certificate{}
	}

	splits := strings.Split(forwardedClientCertificate, ";")
	for _, split := range splits {
		splitKeyVal := strings.Split(split, "=")
		if len(splitKeyVal) == 2 {
			key := splitKeyVal[0]
			val := splitKeyVal[1]

			switch key {
			case "Cert", "Chain":
				cert := strings.Replace(val, "\"", "", -1)
				decodedCert, _ := url.QueryUnescape(cert)
				block, _ := pem.Decode([]byte(decodedCert))
				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					extractor.logger.Warnf("request includes header %s but could not decode certificate. Skipping: %s", envoyClientCertificateHeader, err)
					continue
				}

				return []*x509.Certificate{certificate}
			}
		}
	}

	return []*x509.Certificate{}
}
