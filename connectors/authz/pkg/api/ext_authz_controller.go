package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	start := time.Now()
	method := strings.ToUpper(c.Request.Method)
	incomingURL := c.Request.URL.RequestURI()
	originalURL, path := extAuthzOriginalURL(c)
	headers := extAuthzHeaders(c.Request.Header)

	log := ctrl.logger.WithFields(logrus.Fields{
		"ext_authz_method":       method,
		"ext_authz_incoming_url": incomingURL,
		"ext_authz_original_url": originalURL,
		"ext_authz_path":         path,
	})

	// 1. Extract auth material from Envoy-forwarded headers.
	authType, authMaterial, err := extractAuthFromEnvoyHeaders(headers)
	if err != nil {
		log.WithError(err).Debug("no valid auth credential in ext_authz request")
		logExtAuthzDecision(log, start, http.StatusForbidden, false, "no valid auth credential", nil, nil, "", err)
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
			logExtAuthzDecision(log, start, http.StatusForbidden, false, "no matching principals found", nil, nil, "", err)
			c.Status(http.StatusForbidden)
			return
		}
		log.WithError(err).Error("ext_authz: principal resolution error")
		logExtAuthzDecision(log, start, http.StatusInternalServerError, false, "principal resolution failed", nil, nil, "", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	reqCtx = enrichContextWithMatchedPrincipals(reqCtx, matchedPrincipals)
	c.Request = c.Request.WithContext(reqCtx)
	evaluatedPolicyIDs := policyIDs(policies)

	// 3. Evaluate HTTP policy rules.
	allowed, matchedPolicyID, err := ctrl.engine.CheckHTTP(reqCtx, policies, method, path)
	if err != nil {
		log.WithError(err).Error("ext_authz: http engine error")
		logExtAuthzDecision(log, start, http.StatusInternalServerError, false, "http authorization check failed", matchedPrincipals, evaluatedPolicyIDs, matchedPolicyID, err)
		c.Status(http.StatusInternalServerError)
		return
	}

	if !allowed {
		logExtAuthzDecision(log, start, http.StatusForbidden, false, "no http_rule grants access to this route", matchedPrincipals, evaluatedPolicyIDs, matchedPolicyID, nil)
		c.Status(http.StatusForbidden)
		return
	}

	if len(matchedPrincipals) > 0 {
		c.Header("x-current-user", matchedPrincipals[0])
	}
	logExtAuthzDecision(log, start, http.StatusOK, true, "http_rule grants access to this route", matchedPrincipals, evaluatedPolicyIDs, matchedPolicyID, nil)
	c.Status(http.StatusOK)
}

func logExtAuthzDecision(log *logrus.Entry, start time.Time, statusCode int, allowed bool, reason string, matchedPrincipals []string, evaluatedPolicyIDs []string, matchedPolicyID string, err error) {
	fields := logrus.Fields{
		"allowed":              allowed,
		"decision":             extAuthzDecisionLabel(allowed, statusCode),
		"decision_duration_ms": time.Since(start).Milliseconds(),
		"evaluated_policy_ids": evaluatedPolicyIDs,
		"matched_policy_id":    matchedPolicyID,
		"matched_principal":    firstString(matchedPrincipals),
		"matched_principals":   matchedPrincipals,
		"reason":               reason,
		"status_code":          statusCode,
	}
	if err != nil {
		fields["error"] = err.Error()
	}

	entry := log.WithFields(fields)
	if statusCode >= http.StatusInternalServerError {
		entry.Error("ext_authz decision")
		return
	}
	entry.Info("ext_authz decision")
}

func extAuthzDecisionLabel(allowed bool, statusCode int) string {
	if allowed {
		return "allow"
	}
	if statusCode >= http.StatusInternalServerError {
		return "error"
	}
	return "deny"
}

func policyIDs(policies *engine.PolicyRegistry) []string {
	if policies == nil {
		return nil
	}
	ids := make([]string, 0, len(policies.GetAll()))
	for _, policy := range policies.GetAll() {
		ids = append(ids, policy.ID)
	}
	return ids
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
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

func extAuthzOriginalURL(c *gin.Context) (originalURL string, path string) {
	req := c.Request
	for _, header := range []string{"x-envoy-original-path", "x-forwarded-uri", "x-original-uri"} {
		if value := req.Header.Get(header); value != "" {
			return splitExtAuthzOriginalURL(value)
		}
	}

	if value := c.Param("original_url"); value != "" {
		if !strings.HasPrefix(value, "/") {
			value = "/" + value
		}
		if req.URL.RawQuery != "" && !strings.Contains(value, "?") {
			value += "?" + req.URL.RawQuery
		}
		return splitExtAuthzOriginalURL(value)
	}

	return splitExtAuthzOriginalURL(req.URL.RequestURI())
}

func splitExtAuthzOriginalURL(value string) (originalURL string, path string) {
	if value == "" {
		return "", ""
	}
	if !strings.HasPrefix(value, "/") && !strings.Contains(value, "://") {
		value = "/" + value
	}

	parsed, err := url.Parse(value)
	if err == nil && parsed.Path != "" {
		return parsed.RequestURI(), parsed.Path
	}

	if idx := strings.Index(value, "?"); idx >= 0 {
		return value, value[:idx]
	}
	return value, value
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
