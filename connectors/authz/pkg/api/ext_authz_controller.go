package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/sirupsen/logrus"
)

// ExtAuthzController handles the Envoy ext_authz HTTP check endpoint.
type ExtAuthzController struct {
	engine   *engine.Engine
	resolver *service.IdentityResolver
	logger   *logrus.Entry
}

// NewExtAuthzController creates an ExtAuthzController.
func NewExtAuthzController(eng *engine.Engine, resolver *service.IdentityResolver, logger *logrus.Entry) *ExtAuthzController {
	return &ExtAuthzController{engine: eng, resolver: resolver, logger: logger}
}

// Check handles Envoy's HTTP ext_authz request.
// Envoy's HTTP auth service mode forwards an ordinary HTTP request to this service.
// The response contract follows Envoy's example HTTP auth service: HTTP 200 allows
// the request, non-2xx denies it, and response headers can be propagated upstream.
func (ctrl *ExtAuthzController) Check(c *gin.Context) {
	method := strings.ToUpper(c.Request.Method)
	path := extAuthzOriginalPath(c.Request)
	headers := extAuthzHeaders(c.Request.Header)

	log := ctrl.logger.WithFields(logrus.Fields{
		"ext_authz_method": method,
		"ext_authz_path":   path,
	})

	// 1. Extract auth material from Envoy-forwarded headers.
	authType, authMaterial, err := extractAuthFromEnvoyHeaders(headers)
	if err != nil {
		log.WithError(err).Debug("no valid auth credential in ext_authz request")
		c.Status(http.StatusForbidden)
		return
	}

	// 2. Enrich context for logging, then resolve principals.
	reqCtx := enrichContextByAuthMaterial(c.Request.Context(), authType, authMaterial)
	c.Request = c.Request.WithContext(reqCtx)

	policies, matchedPrincipals, err := ctrl.resolver.Resolve(reqCtx, authMaterial, authType)
	if err != nil {
		if errors.Is(err, service.ErrNoMatch) {
			log.Debug("ext_authz: no matching principals")
			c.Status(http.StatusForbidden)
			return
		}
		log.WithError(err).Error("ext_authz: principal resolution error")
		c.Status(http.StatusInternalServerError)
		return
	}

	reqCtx = enrichContextWithMatchedPrincipals(reqCtx, matchedPrincipals)
	c.Request = c.Request.WithContext(reqCtx)

	// 3. Evaluate HTTP policy rules.
	allowed, matchedPolicyID, err := ctrl.engine.CheckHTTP(reqCtx, policies, method, path)
	if err != nil {
		log.WithError(err).Error("ext_authz: http engine error")
		c.Status(http.StatusInternalServerError)
		return
	}

	log.WithFields(logrus.Fields{
		"allowed":            allowed,
		"matched_principals": matchedPrincipals,
		"matched_policy":     matchedPolicyID,
	}).Info("ext_authz decision")

	if !allowed {
		c.Status(http.StatusForbidden)
		return
	}

	if len(matchedPrincipals) > 0 {
		c.Header("x-current-user", matchedPrincipals[0])
	}
	c.Status(http.StatusOK)
}

func extAuthzHeaders(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		out[strings.ToLower(key)] = values[0]
	}
	return out
}

func extAuthzOriginalPath(req *http.Request) string {
	for _, header := range []string{"x-envoy-original-path", "x-forwarded-uri", "x-original-uri"} {
		if value := req.Header.Get(header); value != "" {
			return value
		}
	}
	return req.URL.RequestURI()
}

// extractAuthFromEnvoyHeaders derives (authType, authMaterial, error) from Envoy-forwarded
// request headers. XFCC (mTLS cert) takes precedence over Bearer token when both are present,
// because mutual TLS identity is cryptographically stronger.
func extractAuthFromEnvoyHeaders(headers map[string]string) (authType string, authMaterial interface{}, err error) {
	if xfcc, ok := headers["x-forwarded-client-cert"]; ok && xfcc != "" {
		pemStr, parseErr := parseXFCCCert(xfcc)
		if parseErr != nil {
			return "", nil, fmt.Errorf("invalid x-forwarded-client-cert: %w", parseErr)
		}
		return "x509", pemStr, nil
	}
	if auth, ok := headers["authorization"]; ok && strings.HasPrefix(auth, "Bearer ") {
		// OIDCMatcher.extractOIDCClaims strips the "Bearer " prefix itself.
		return "oidc", auth, nil
	}
	return "", nil, fmt.Errorf("no recognised auth credential (XFCC or Bearer token) in request headers")
}

// parseXFCCCert extracts and URL-decodes the PEM certificate string from an
// x-forwarded-client-cert (XFCC) header value. The XFCC format is:
//
//	Cert="<url-encoded-PEM>";Chain="<url-encoded-PEM>";...
func parseXFCCCert(xfcc string) (string, error) {
	for _, part := range strings.Split(xfcc, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "Cert=") {
			continue
		}
		encoded := strings.TrimPrefix(part, "Cert=")
		encoded = strings.Trim(encoded, "\"")
		decoded, err := url.QueryUnescape(encoded)
		if err != nil {
			return "", fmt.Errorf("url-decode XFCC Cert field: %w", err)
		}
		return decoded, nil
	}
	return "", fmt.Errorf("XFCC header has no Cert= field")
}
