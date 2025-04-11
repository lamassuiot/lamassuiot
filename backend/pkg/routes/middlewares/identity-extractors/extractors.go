package identityextractors

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
)

const CtxAuthMode = "REQ_AUTH_MODE"
const CtxAuthID = "REQ_AUTH_ID"

type IdentityExtractor string

const (
	IdentityExtractorNoAuth IdentityExtractor = "NO_AUTH"
)

type HttpAuthReqExtractor interface {
	ExtractAuthentication(ctx *gin.Context, req http.Request)
	Name() string
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
		parentTracer := c.Value("otel-go-contrib-tracer")
		tracer, hasTracer := parentTracer.(trace.Tracer)
		var opSpanCtx context.Context
		var span trace.Span

		if hasTracer {
			opSpanCtx, span = tracer.Start(c.Request.Context(), "Identity Extractor Middleware")
		}

		for _, authExtractor := range authExtractors {
			var authExtractorSpan trace.Span
			if hasTracer {
				_, authExtractorSpan = tracer.Start(opSpanCtx, fmt.Sprintf("Auth Extractor - %s", authExtractor.Name()))
			}

			authExtractor.ExtractAuthentication(c, *c.Request)
			authExtractorSpan.End()
		}

		UpdateContextWithRequest(c, c.Request.Header)
		span.End()

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
