package identityextractors

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/gin-gonic/gin"
	clientcertificateextractor "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors/client-certificate-extractor"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

const (
	IdentityExtractorClientCertificate IdentityExtractor = "CLIENT_CERTIFICATE"
)

type ClientCertificateExtractor struct {
	logger *logrus.Entry
}

func (extractor ClientCertificateExtractor) ExtractAuthentication(ctx *gin.Context, req http.Request) {
	var crts []*x509.Certificate
	var err error

	crts, err = extractor.getCertificateFromHeader(req.Header)
	if err != nil {
		extractor.logger.Tracef("something went wrong while processing headers: %s", err)
	} else if crts == nil {
		//no (valid) certificate in the header. check if a certificate can be obtained from client TLS connection
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			extractor.logger.Trace("Using certificate presented in peer connection")
			crts = req.TLS.PeerCertificates
		} else {
			extractor.logger.Trace("No certificate presented in peer connection")
		}
	}

	if len(crts) > 0 {
		crt := crts[0]
		crtS := models.X509Certificate(*crt)

		ctx.Set(core.LamassuContextKeyAuthType, string(IdentityExtractorClientCertificate))
		ctx.Set(core.LamassuContextKeyAuthCredentialString, crtS.String())
		ctx.Set(core.LamassuContextKeyAuthCredentialStruct, crt)
		ctx.Set(core.LamassuContextKeyAuthID, crt.Subject.CommonName)
		ctx.Set(core.LamassuContextKeyAuthContext, map[string]interface{}{
			"crt": crtS.String(),
		})

		reqCtx := req.Context()
		reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthCredentialStruct, crt)
		reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthCredentialString, crtS.String())
		reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthType, string(IdentityExtractorClientCertificate))
		reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthID, crt.Subject.CommonName)
		reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthContext, map[string]interface{}{
			"crt": crtS.String(),
		})
		ctx.Request = ctx.Request.WithContext(reqCtx)
	}
}

type ClientCertificateReqExtractor interface {
	ExtractCertificate(http.Header) []*x509.Certificate
}

func (extractor ClientCertificateExtractor) getCertificateFromHeader(h http.Header) ([]*x509.Certificate, error) {
	headerExtractors := []ClientCertificateReqExtractor{
		clientcertificateextractor.NewEnvoyClientCertificateExtractor(extractor.logger),
		clientcertificateextractor.NewNginxClientCertificateExtractor(extractor.logger),
		clientcertificateextractor.NewAwsALBClientCertificateExtractor(extractor.logger),
	}

	for _, headerExtractor := range headerExtractors {
		certs := headerExtractor.ExtractCertificate(h)

		if len(certs) > 0 {
			return certs, nil
		}
	}

	return nil, nil
}
