package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/authz"
)

type AuthzController struct {
	engine   *authz.Engine
	resolver *authz.IdentityResolver
}

func NewAuthzController(engine *authz.Engine, resolver *authz.IdentityResolver) *AuthzController {
	return &AuthzController{
		engine:   engine,
		resolver: resolver,
	}
}

// Authorize godoc
// @Summary Check authorization
// @Description Check if a user can perform an action on an entity
// @Tags authorization
// @Accept json
// @Produce json
// @Param request body dto.AuthorizeRequest true "Authorization request"
// @Success 200 {object} dto.AuthorizeResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/authz/authorize [post]
func (ctrl *AuthzController) Authorize(c *gin.Context) {
	var req dto.AuthorizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	if err := ctrl.validateEntityNamespace(req.Namespace, req.SchemaName, req.EntityType); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	policies, err := ctrl.resolver.GetPoliciesForPrincipal(c.Request.Context(), req.PrincipalID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to get principal policies",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	entityKey, err := resolveEntityKey(ctrl.engine.GetSchemas(), req.SchemaName, req.EntityType, req.EntityKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid entity key",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	allowed, err := ctrl.engine.Authorize(policies, req.Namespace, req.SchemaName, req.Action, req.EntityType, entityKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Authorization check failed",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, dto.AuthorizeResponse{
		Allowed:    allowed,
		Namespace:  req.Namespace,
		SchemaName: req.SchemaName,
		EntityType: req.EntityType,
		EntityKey:  entityKey,
		Action:     req.Action,
	})
}

// GetFilter godoc
// @Summary Get list filter
// @Description Get SQL filter for listing entities
// @Tags authorization
// @Accept json
// @Produce json
// @Param request body dto.GetFilterRequest true "Filter request"
// @Success 200 {object} dto.GetFilterResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/authz/filter [post]
func (ctrl *AuthzController) GetFilter(c *gin.Context) {
	var req dto.GetFilterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	if err := ctrl.validateEntityNamespace(req.Namespace, req.SchemaName, req.EntityType); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	policies, err := ctrl.resolver.GetPoliciesForPrincipal(c.Request.Context(), req.PrincipalID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to get principal policies",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	filterSQL, err := ctrl.engine.GetListFilter(policies, req.Namespace, req.SchemaName, req.EntityType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to generate filter",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, dto.GetFilterResponse{
		Namespace:   req.Namespace,
		SchemaName:  req.SchemaName,
		EntityType:  req.EntityType,
		FilterQuery: filterSQL,
	})
}

// MatchAndAuthorize godoc
// @Summary Check authorization with principal matching
// @Description Match principals from auth material and check if they can perform an action on an entity
// @Tags authorization
// @Accept json
// @Produce json
// @Param request body dto.MatchAndAuthorizeRequest true "Match and authorization request"
// @Success 200 {object} dto.MatchAndAuthorizeResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/authz/match/authorize [post]
func (ctrl *AuthzController) MatchAndAuthorize(c *gin.Context) {
	var req dto.MatchAndAuthorizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	if err := ctrl.validateEntityNamespace(req.Namespace, req.SchemaName, req.EntityType); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	policies, matchedPrincipals, err := ctrl.resolver.Resolve(c.Request.Context(), req.AuthMaterial, req.AuthType)
	if err != nil {
		if errors.Is(err, authz.ErrNoMatch) {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Error:   "Authentication failed",
				Details: map[string]string{"reason": "No matching principals found"},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to resolve principals",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	entityKey, err := resolveEntityKey(ctrl.engine.GetSchemas(), req.SchemaName, req.EntityType, req.EntityKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid entity key",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	allowed, err := ctrl.engine.Authorize(policies, req.Namespace, req.SchemaName, req.Action, req.EntityType, entityKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Authorization check failed",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, dto.MatchAndAuthorizeResponse{
		Allowed:           allowed,
		Namespace:         req.Namespace,
		SchemaName:        req.SchemaName,
		EntityType:        req.EntityType,
		EntityKey:         entityKey,
		Action:            req.Action,
		MatchedPrincipals: matchedPrincipals,
	})
}

// MatchAndGetFilter godoc
// @Summary Get list filter with principal matching
// @Description Match principals from auth material and get SQL filter for listing entities
// @Tags authorization
// @Accept json
// @Produce json
// @Param request body dto.MatchAndGetFilterRequest true "Match and filter request"
// @Success 200 {object} dto.MatchAndGetFilterResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/authz/match/filter [post]
func (ctrl *AuthzController) MatchAndGetFilter(c *gin.Context) {
	var req dto.MatchAndGetFilterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	if err := ctrl.validateEntityNamespace(req.Namespace, req.SchemaName, req.EntityType); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	policies, matchedPrincipals, err := ctrl.resolver.Resolve(c.Request.Context(), req.AuthMaterial, req.AuthType)
	if err != nil {
		if errors.Is(err, authz.ErrNoMatch) {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Error:   "Authentication failed",
				Details: map[string]string{"reason": "No matching principals found"},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to resolve principals",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	filterSQL, err := ctrl.engine.GetListFilter(policies, req.Namespace, req.SchemaName, req.EntityType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to generate filter",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	fmt.Println(filterSQL)

	c.JSON(http.StatusOK, dto.MatchAndGetFilterResponse{
		Namespace:         req.Namespace,
		SchemaName:        req.SchemaName,
		EntityType:        req.EntityType,
		FilterQuery:       filterSQL,
		MatchedPrincipals: matchedPrincipals,
	})
}

func validateEntityIdentifier(schemaName, entityType string) error {
	entityType = strings.TrimSpace(entityType)
	if strings.Contains(entityType, ".") {
		return fmt.Errorf("entityType must be unqualified; provide schemaName separately")
	}

	schemaName = strings.TrimSpace(schemaName)
	if schemaName == "" {
		return fmt.Errorf("schemaName is required")
	}

	if entityType == "" {
		return fmt.Errorf("entityType is required")
	}

	return nil
}

func (ctrl *AuthzController) validateEntityNamespace(namespace, schemaName, entityType string) error {
	if err := validateEntityIdentifier(schemaName, entityType); err != nil {
		return err
	}

	schema, err := ctrl.engine.GetSchemas().GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return fmt.Errorf("invalid entity reference '%s.%s': %w", schemaName, entityType, err)
	}

	if schema.ConfigSchema != namespace {
		return fmt.Errorf("entity '%s.%s' does not belong to namespace '%s'", schemaName, entityType, namespace)
	}

	return nil
}

// resolveEntityKey converts a FlexEntityKey to a concrete map[string]string.
// Returning nil is valid for global actions (no entity required).
// If the key is a plain string, the schema's single PK column is resolved automatically;
// composite-PK schemas require the object form.
func resolveEntityKey(schemas *authz.SchemaRegistry, schemaName, entityType string, key dto.FlexEntityKey) (map[string]string, error) {
	if key.IsEmpty() {
		return nil, nil
	}
	if !key.IsString() {
		return key.Map(), nil
	}
	schema, err := schemas.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve entity key: %w", err)
	}
	if len(schema.PrimaryKeys) != 1 {
		return nil, fmt.Errorf("plain string entityKey is only valid for single-column PK schemas; use an object for composite PKs")
	}
	return map[string]string{schema.PrimaryKeys[0]: key.Str()}, nil
}
