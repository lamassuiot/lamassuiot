package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/api/dto"
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

// Check handles POST /v1/ext_authz/check.
// It accepts Envoy's CheckRequest JSON body, resolves the caller's principal from
// credentials in the request headers, evaluates HTTP policy rules, and returns
// HTTP 200 (allowed) or HTTP 403 (denied). HTTP 401 is returned when credentials
// are absent or match no registered principal.
func (ctrl *ExtAuthzController) Check(c *gin.Context) {
	var req dto.ExtAuthzCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request body",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	if req.Attributes == nil || req.Attributes.Request == nil || req.Attributes.Request.HTTP == nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error: "attributes.request.http is required",
		})
		return
	}

	httpReq := req.Attributes.Request.HTTP
	method := strings.ToUpper(httpReq.Method)
	path := httpReq.Path

	log := ctrl.logger.WithFields(logrus.Fields{
		"ext_authz_method": method,
		"ext_authz_path":   path,
	})

	// 1. Extract auth material from Envoy-forwarded headers.
	authType, authMaterial, err := extractAuthFromEnvoyHeaders(httpReq.Headers)
	if err != nil {
		log.WithError(err).Debug("no valid auth credential in ext_authz request")
		c.JSON(http.StatusUnauthorized, dto.ExtAuthzCheckResponse{
			Allowed: false,
			Reason:  "no valid auth credential: " + err.Error(),
		})
		return
	}

	// 2. Enrich context for logging, then resolve principals.
	reqCtx := enrichContextByAuthMaterial(c.Request.Context(), authType, authMaterial)
	c.Request = c.Request.WithContext(reqCtx)

	policies, matchedPrincipals, err := ctrl.resolver.Resolve(reqCtx, authMaterial, authType)
	if err != nil {
		if errors.Is(err, service.ErrNoMatch) {
			log.Debug("ext_authz: no matching principals")
			c.JSON(http.StatusUnauthorized, dto.ExtAuthzCheckResponse{
				Allowed: false,
				Reason:  "no matching principals found",
			})
			return
		}
		log.WithError(err).Error("ext_authz: principal resolution error")
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "principal resolution failed",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	reqCtx = enrichContextWithMatchedPrincipals(reqCtx, matchedPrincipals)
	c.Request = c.Request.WithContext(reqCtx)

	// 3. Evaluate HTTP policy rules.
	allowed, matchedPolicyID, err := ctrl.engine.CheckHTTP(reqCtx, policies, method, path)
	if err != nil {
		log.WithError(err).Error("ext_authz: http engine error")
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "HTTP authorization check failed",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	log.WithFields(logrus.Fields{
		"allowed":            allowed,
		"matched_principals": matchedPrincipals,
		"matched_policy":     matchedPolicyID,
	}).Info("ext_authz decision")

	if !allowed {
		c.JSON(http.StatusForbidden, dto.ExtAuthzCheckResponse{
			Allowed:           false,
			MatchedPrincipals: matchedPrincipals,
			Reason:            "no http_rule grants access to this route",
		})
		return
	}

	c.JSON(http.StatusOK, dto.ExtAuthzCheckResponse{
		Allowed:           true,
		MatchedPolicyID:   matchedPolicyID,
		MatchedPrincipals: matchedPrincipals,
	})
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
