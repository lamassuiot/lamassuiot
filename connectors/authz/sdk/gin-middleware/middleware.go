package middleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/core"
	"github.com/sirupsen/logrus"
)

// AuthzMiddleware provides authorization checking for HTTP requests
type AuthzMiddleware struct {
	engine            core.AuthzEngine
	entityType        string
	entityPrimaryKeys []string
	schemaName        string
	namespace         string
	logger            *logrus.Entry
}

// NewSimpleAuthzMiddleware creates middleware for entities whose primary key column is "id".
// AuthzCheck reads the entity key from the URL path parameter :id, e.g.:
//
//	router.GET("/organizations/:id", mw.AuthzCheck("read"), handler)
//
// For entities whose PK column is not "id" (e.g. device_id), use NewCompositeAuthzMiddleware.
func NewSimpleAuthzMiddleware(engine core.AuthzEngine, namespace, schemaName, entityType string, logger *logrus.Entry) *AuthzMiddleware {
	return &AuthzMiddleware{engine: engine, namespace: namespace, schemaName: schemaName, entityType: entityType, entityPrimaryKeys: []string{"id"}, logger: logger}
}

// NewCompositeAuthzMiddleware creates middleware for entities with a composite primary key.
// Each element of pkColumns must match a URL path parameter name used in the route, e.g.:
//
//	router.GET("/tenants/:tenant_id/devices/:device_id", mw.AuthzCheck("read"), handler)
//	→ NewCompositeAuthzMiddleware(engine, "iot_schema", "public", "device", []string{"tenant_id", "device_id"}, logger)
func NewCompositeAuthzMiddleware(engine core.AuthzEngine, namespace, schemaName, entityType string, pkColumns []string, logger *logrus.Entry) *AuthzMiddleware {
	return &AuthzMiddleware{engine: engine, namespace: namespace, schemaName: schemaName, entityType: entityType, entityPrimaryKeys: pkColumns, logger: logger}
}

// AuthzCheckCustom is the core check handler. entityKeyFunc is called on each request
// to build the entity key map, giving callers full control over how the key is extracted
// (URL path params, query params, headers, decoded body, etc.).
func (m *AuthzMiddleware) AuthzCheckCustom(action string, entityKeyFunc func(*gin.Context) map[string]string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow admin bypass with special header
		if c.GetHeader("X-Principal-ID") == "admin-mode" {
			c.Next()
			return
		}

		authType, authMaterial, err := extractAuthInputs(c)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": err.Error()})
			return
		}

		entityKey := entityKeyFunc(c)

		authorized, matchedPrincipals, err := m.engine.MatchAndAuthorize(authType, authMaterial, m.namespace, m.schemaName, action, m.entityType, entityKey)
		if err != nil {
			m.logger.Errorf("error in MatchAndAuthorize: %v", err)
			c.AbortWithStatusJSON(500, gin.H{"error": "Authorization service error", "details": err.Error()})
			return
		}

		if !authorized {
			c.AbortWithStatusJSON(403, gin.H{"error": "Access denied"})
			return
		}

		// Store matched principals in context for potential use by handlers
		c.Set("matched_principals", matchedPrincipals)
		c.Next()
	}
}

// AuthzCheckCustomField extracts the entity key from the named URL path params.
func (m *AuthzMiddleware) AuthzCheckCustomField(action string, paramFields []string) gin.HandlerFunc {
	return m.AuthzCheckCustom(action, func(c *gin.Context) map[string]string {
		pk := make(map[string]string, len(paramFields))
		for _, field := range paramFields {
			pk[field] = c.Param(field)
		}
		return pk
	})
}

// AuthzCheck extracts the entity key from URL path params using the primary key columns
// configured on the middleware.
func (m *AuthzMiddleware) AuthzCheck(action string) gin.HandlerFunc {
	return m.AuthzCheckCustomField(action, m.entityPrimaryKeys)
}

func (s *AuthzMiddleware) AuthListCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow admin bypass with special header
		if c.GetHeader("X-Principal-ID") == "admin-mode" {
			c.Next()
			return
		}

		authType, authMaterial, err := extractAuthInputs(c)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": err.Error()})
			return
		}

		authorizedList, matchedPrincipals, err := s.engine.MatchAndGetFilter(authType, authMaterial, s.namespace, s.schemaName, s.entityType)
		if err != nil {
			s.logger.Errorf("error in MatchAndGetFilter: %v", err)
			c.AbortWithStatusJSON(500, gin.H{"error": "Authorization service error", "details": err.Error()})
			return
		}

		if len(authorizedList) != 0 {
			c.Set("authz_query", authorizedList)

			reqCtx := context.WithValue(c.Request.Context(), "authz_query", authorizedList)
			c.Request = c.Request.WithContext(reqCtx)
		}

		c.Set("matched_principals", matchedPrincipals)
		c.Next()
	}
}

func extractAuthInputs(c *gin.Context) (string, string, error) {
	authType, authTypeExists := c.Get("lamassu.io/ctx/auth-type")
	authCred, authCredExists := c.Get("lamassu.io/ctx/auth-credential-string")

	if !authCredExists || !authTypeExists {
		return "", "", fmt.Errorf("missing either auth-type or auth-credential-string")
	}

	authTypeString, ok := authType.(string)
	if !ok {
		return "", "", fmt.Errorf("auth-type is not actually a string")
	}

	authCredString, ok := authCred.(string)
	if !ok {
		return "", "", fmt.Errorf("auth-credential-string is not actually a string")
	}

	switch strings.ToLower(authTypeString) {
	case "x509":
		return "x509", authCredString, nil
	case "jwt":
		return "oidc", authCredString, nil
	default:
		return "", "", fmt.Errorf("auth-type not supported")
	}
}
