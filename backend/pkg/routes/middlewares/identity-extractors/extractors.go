package identityextractors

import (
	"crypto/x509"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

const CtxAuthMode = "REQ_AUTH_MODE"
const CtxAuthID = "REQ_AUTH_ID"

type IdentityExtractor string

const (
	IdentityExtractorNoAuth IdentityExtractor = "NO_AUTH"
)

type HttpAuthReqExtractor interface {
	ExtractAuthentication(ctx *gin.Context, req http.Request)
}

func RequestMetadataToContextMiddleware(logger *logrus.Entry) gin.HandlerFunc {
	authExtractors := []HttpAuthReqExtractor{
		ClientCertificateExtractor{
			logger: logger,
		},

		JWTExtractor{
			logger: logger,
		},
	}

	return func(c *gin.Context) {
		for _, authExtractor := range authExtractors {
			authExtractor.ExtractAuthentication(c, *c.Request)
		}

		UpdateContextWithRequest(c, c.Request.Header)
		c.Next()
	}
}

func UpdateContextWithRequest(ctx *gin.Context, headers http.Header) {
	authMode := ""
	callerID := ""

	jwtAny, hasValue := ctx.Get(string(IdentityExtractorJWT))
	if hasValue {
		token := jwtAny.(*jwt.Token)
		// Access the claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if ok {
			// Extract the sub claim
			sub, ok := claims["sub"].(string)
			if ok {
				authMode = "jwt"
				callerID = sub
			}
		}
	}

	clientCertAny, hasValue := ctx.Get(string(IdentityExtractorClientCertificate))
	if hasValue {
		clientCert := clientCertAny.(*x509.Certificate)
		authMode = "crt"
		callerID = clientCert.Subject.CommonName
	}

	if authMode != "" {
		ctx.Set(CtxAuthMode, authMode)
	}

	if callerID != "" {
		ctx.Set(CtxAuthID, callerID)
	}
}
