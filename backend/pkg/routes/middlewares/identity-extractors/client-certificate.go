package identityextractors

import (
	"crypto/x509"
	"net/http"

	"github.com/gin-gonic/gin"
	clientcertificateextractor "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors/client-certificate-extractor"
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

type ClientCertificateReqExtractor interface {
	ExtractCertificate(http.Header) []*x509.Certificate
}

func (extractor ClientCertificateExtractor) getCertificateFromHeader(h http.Header) (*x509.Certificate, error) {
	headerExtractors := []ClientCertificateReqExtractor{
		clientcertificateextractor.NewEnvoyClientCertificateExtractor(extractor.logger),
		clientcertificateextractor.NewNginxClientCertificateExtractor(extractor.logger),
	}

	for _, headerExtractor := range headerExtractors {
		certs := headerExtractor.ExtractCertificate(h)

		if len(certs) > 0 {
			return certs[0], nil
		}
	}

	return nil, nil
}
