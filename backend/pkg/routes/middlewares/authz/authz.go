package authz

import (
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/sirupsen/logrus"
)

type Role string

const (
	RoleSuperAdmin  Role = "super_admin"
	RoleCAAdmin     Role = "ca_admin"
	RoleCAUser      Role = "ca_user"
	RoleCAIssuer    Role = "ca_issuer"
	RoleCASigner    Role = "ca_signer"
	RoleCertAdmin   Role = "cert_admin"
	RoleCertUser    Role = "cert_user"
	RoleDeviceAdmin Role = "device_admin"
	RoleDeviceUser  Role = "device_user"
	RoleDMSAdmin    Role = "dms_admin"
	RoleDMSUser     Role = "dms_user"
)

var DefaultRoleMapping = map[Role]string{
	RoleSuperAdmin:  "super_admin",
	RoleCAAdmin:     "ca_admin",
	RoleCAUser:      "ca_user",
	RoleCAIssuer:    "ca_issuer",
	RoleCASigner:    "ca_signer",
	RoleCertAdmin:   "cert_admin",
	RoleCertUser:    "cert_user",
	RoleDeviceAdmin: "device_admin",
	RoleDeviceUser:  "device_user",
	RoleDMSAdmin:    "dms_admin",
	RoleDMSUser:     "dms_user",
}

type LamassuAuthorizationMiddleware struct {
	logger       *logrus.Entry
	roleClaim    string
	roleMappings map[Role]string
	enforce      bool
}

func NewAuthorizationMiddleware(logger *logrus.Entry, roleClaim string, roleMappings map[Role]string, enforce bool) (LamassuAuthorizationMiddleware, error) {
	roles := DefaultRoleMapping
	for k, v := range roleMappings {
		if _, exists := roles[k]; exists {
			roles[k] = v
		}
	}

	return LamassuAuthorizationMiddleware{
		logger:       logger,
		roleClaim:    roleClaim,
		roleMappings: roles,
		enforce:      enforce,
	}, nil
}

func (mw *LamassuAuthorizationMiddleware) Use(allowedRoles []Role) func(c *gin.Context) {
	return func(c *gin.Context) {
		// If authorization is disabled, skip
		if !mw.enforce {
			c.Next()
			return
		}

		// Get the user
		rawToken, exists := c.Get(string(identityextractors.IdentityExtractorJWT))
		if !exists {
			c.AbortWithStatusJSON(401, gin.H{"error": "no jwt token found"})
			return
		}

		// Access the claims
		token := rawToken.(*jwt.Token)
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid jwt token"})
			return
		}

		// Extract the roles
		rawRoles, exists := getNestedKey(claims, mw.roleClaim)
		if !exists {
			c.AbortWithStatusJSON(403, gin.H{"error": "no roles found in jwt token"})
			return
		}

		rawRolesIface, ok := rawRoles.([]interface{})
		if !ok {
			c.AbortWithStatusJSON(403, gin.H{"error": "invalid roles in jwt token"})
			return
		}

		roles := []string{}
		for _, v := range rawRolesIface {
			if str, ok := v.(string); ok {
				roles = append(roles, str)
			}
		}

		// Check if super admin
		if hasRole := slices.Contains(roles, mw.roleMappings[RoleSuperAdmin]); hasRole {
			c.Next()
			return
		}

		// Check if the user has the required role
		for _, role := range allowedRoles {
			if hasRole := slices.Contains(roles, mw.roleMappings[role]); hasRole {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
	}
}

// getNestedKey retrieves the value of a nested key from a map
func getNestedKey(data map[string]any, key string) (any, bool) {
	parts := strings.SplitN(key, ".", 2) // Split into first key and remaining keys

	val, exists := data[parts[0]]
	if !exists {
		return nil, false
	}

	// If there's more to the key, recurse into the nested map
	if len(parts) > 1 {
		if submap, ok := val.(map[string]any); ok {
			return getNestedKey(submap, parts[1])
		}
		return nil, false
	}

	// If this was the last key, return the value
	return val, true
}
