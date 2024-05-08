package identityextractors

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const (
	IdentityExtractorClientCertificate IdentityExtractor = "CLIENT_CERTIFICATE"
)

type ClientCertificateExtractor struct {
	logger *logrus.Entry
}

func (extractor ClientCertificateExtractor) ExtractAuthentication(ctx *gin.Context, req http.Request) {
	var crt *x509.Certificate
	var err error

	crt, err = extractor.getCertificateFromHeader(req.Header)
	if err != nil {
		extractor.logger.Tracef("something went wrong while processing headers: %s", err)
	} else if crt != nil {
		ctx.Set(string(IdentityExtractorClientCertificate), crt)
		return
	}

	//no (valid) certificate in the header. check if a certificate can be obtained from client TLS connection
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		extractor.logger.Trace("Using certificate presented in peer connection")
		crt = req.TLS.PeerCertificates[0]
	} else {
		extractor.logger.Trace("No certificate presented in peer connection")
	}

	if crt != nil {
		ctx.Set(string(IdentityExtractorClientCertificate), crt)
	}
}

func (extractor ClientCertificateExtractor) getCertificateFromHeader(h http.Header) (*x509.Certificate, error) {
	headerNames := []string{
		"x-forwarded-client-cert", //envoy and regular nginx use this value
		"ssl-client-cert",
	}

	for _, headerName := range headerNames {
		forwardedClientCertificate := h.Get(headerName)
		if len(forwardedClientCertificate) != 0 {
			extractor.logger.Debugf("attempting envoy-style certificate extraction from header %s", headerName)
			crts := extractor.extractClientCertFromHeaderEnvoyStyle(headerName, forwardedClientCertificate)
			if len(crts) == 0 {
				extractor.logger.Debugf("envoy-style certificate extraction didn't return anything")
			} else {
				return crts[0], nil
			}
		}
	}

	return nil, nil
}

func (extractor ClientCertificateExtractor) extractClientCertFromHeaderEnvoyStyle(headerName, headerString string) []*x509.Certificate {
	extractor.logger.Tracef("got header %s with %s", headerName, headerString)

	splits := strings.Split(headerString, ";")
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
					extractor.logger.Warnf("request includes header %s but could not decode certificate. Skipping: %s", headerName, err)
					continue
				}

				return []*x509.Certificate{certificate}

			}
		}
	}

	return []*x509.Certificate{}
}
