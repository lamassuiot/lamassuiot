package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/service"
	lamassu "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/sirupsen/logrus"
)

type AuthzController struct {
	engine   *engine.Engine
	resolver *service.IdentityResolver
	logger   *logrus.Entry
}

func NewAuthzController(eng *engine.Engine, resolver *service.IdentityResolver, logger *logrus.Entry) *AuthzController {
	return &AuthzController{
		engine:   eng,
		resolver: resolver,
		logger:   logger,
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
		replyBadRequest(c, err)
		return
	}

	if err := ctrl.validateEntityNamespace(req.Namespace, req.SchemaName, req.EntityType); err != nil {
		replyBadRequest(c, err)
		return
	}

	reqCtx := enrichContextByPrincipalID(c.Request.Context(), req.PrincipalID)
	c.Request = c.Request.WithContext(reqCtx)

	policies, err := ctrl.resolver.GetPoliciesForPrincipal(reqCtx, req.PrincipalID)
	if err != nil {
		replyInternalError(c, "Failed to get principal policies", err)
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

	allowed, err := ctrl.engine.Authorize(reqCtx, policies, req.Namespace, req.SchemaName, req.Action, req.EntityType, entityKey)
	if err != nil {
		replyInternalError(c, "Authorization check failed", err)
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
		replyBadRequest(c, err)
		return
	}

	if err := ctrl.validateEntityNamespace(req.Namespace, req.SchemaName, req.EntityType); err != nil {
		replyBadRequest(c, err)
		return
	}

	reqCtx := enrichContextByPrincipalID(c.Request.Context(), req.PrincipalID)
	c.Request = c.Request.WithContext(reqCtx)

	policies, err := ctrl.resolver.GetPoliciesForPrincipal(reqCtx, req.PrincipalID)
	if err != nil {
		replyInternalError(c, "Failed to get principal policies", err)
		return
	}

	filterSQL, err := ctrl.engine.GetListFilter(reqCtx, policies, req.Namespace, req.SchemaName, req.EntityType)
	if err != nil {
		replyInternalError(c, "Failed to generate filter", err)
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
		replyBadRequest(c, err)
		return
	}

	if err := ctrl.validateEntityNamespace(req.Namespace, req.SchemaName, req.EntityType); err != nil {
		replyBadRequest(c, err)
		return
	}

	reqCtx := enrichContextByAuthMaterial(c.Request.Context(), req.AuthType, req.AuthMaterial)
	c.Request = c.Request.WithContext(reqCtx)

	policies, matchedPrincipals, err := ctrl.resolver.Resolve(reqCtx, req.AuthMaterial, req.AuthType)
	if err != nil {
		if errors.Is(err, service.ErrNoMatch) {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Error:   "Authentication failed",
				Details: map[string]string{"reason": "No matching principals found"},
			})
			return
		}
		replyInternalError(c, "Failed to resolve principals", err)
		return
	}

	reqCtx = enrichContextWithMatchedPrincipals(reqCtx, matchedPrincipals)
	c.Request = c.Request.WithContext(reqCtx)

	entityKey, err := resolveEntityKey(ctrl.engine.GetSchemas(), req.SchemaName, req.EntityType, req.EntityKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid entity key",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	allowed, err := ctrl.engine.Authorize(reqCtx, policies, req.Namespace, req.SchemaName, req.Action, req.EntityType, entityKey)
	if err != nil {
		replyInternalError(c, "Authorization check failed", err)
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

// CheckHTTP checks an HTTP route for a known principal and explicit subject attributes.
// @Summary Check HTTP authorization
// @Description Check whether a known principal can access an HTTP route. Subject attributes must be supplied explicitly for this debug path.
// @Tags authorization
// @Accept json
// @Produce json
// @Param request body dto.HTTPAuthzCheckRequest true "HTTP authorization check request"
// @Success 200 {object} dto.HTTPAuthzCheckResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/authz/http/check [post]
func (ctrl *AuthzController) CheckHTTP(c *gin.Context) {
	var req dto.HTTPAuthzCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		replyBadRequest(c, err)
		return
	}
	if err := validateHTTPCheckRequest(req.Request); err != nil {
		replyBadRequest(c, err)
		return
	}

	reqCtx := enrichContextByPrincipalID(c.Request.Context(), req.PrincipalID)
	c.Request = c.Request.WithContext(reqCtx)

	policies, err := ctrl.resolver.GetPoliciesForPrincipal(reqCtx, req.PrincipalID)
	if err != nil {
		replyInternalError(c, "Failed to get principal policies", err)
		return
	}

	attributes := copySubjectAttributes(req.SubjectAttributes)
	subjectPolicies := []engine.SubjectPolicySet{
		{
			Subject: engine.ResolvedSubject{
				PrincipalID: req.PrincipalID,
				Attributes:  attributes,
			},
			Policies: policies,
		},
	}

	result, err := ctrl.engine.CheckHTTPRequest(reqCtx, toEngineHTTPCheckRequest(req.Request, subjectPolicies))
	if err != nil {
		replyInternalError(c, "HTTP authorization check failed", err)
		return
	}

	c.JSON(http.StatusOK, httpCheckResponse(result, []string{req.PrincipalID}, attributes))
}

// MatchAndCheckHTTP resolves a credential, derives subject attributes, and checks an HTTP route.
// @Summary Check HTTP authorization with principal matching
// @Description Resolve principals from auth material and check whether one matched subject can access an HTTP route.
// @Tags authorization
// @Accept json
// @Produce json
// @Param request body dto.MatchHTTPAuthzCheckRequest true "HTTP authorization check request"
// @Success 200 {object} dto.HTTPAuthzCheckResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/authz/match/http/check [post]
func (ctrl *AuthzController) MatchAndCheckHTTP(c *gin.Context) {
	var req dto.MatchHTTPAuthzCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		replyBadRequest(c, err)
		return
	}
	if err := validateHTTPCheckRequest(req.Request); err != nil {
		replyBadRequest(c, err)
		return
	}

	reqCtx := enrichContextByAuthMaterial(c.Request.Context(), req.AuthType, req.AuthMaterial)
	c.Request = c.Request.WithContext(reqCtx)

	subjectPolicies, matchedPrincipals, err := ctrl.resolver.ResolveSubjects(reqCtx, req.AuthMaterial, req.AuthType)
	if err != nil {
		if errors.Is(err, service.ErrNoMatch) {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Error:   "Authentication failed",
				Details: map[string]string{"reason": "No matching principals found"},
			})
			return
		}
		replyInternalError(c, "Failed to resolve principals", err)
		return
	}

	reqCtx = enrichContextWithMatchedPrincipals(reqCtx, matchedPrincipals)
	c.Request = c.Request.WithContext(reqCtx)

	result, err := ctrl.engine.CheckHTTPRequest(reqCtx, toEngineHTTPCheckRequest(req.Request, subjectPolicies))
	if err != nil {
		replyInternalError(c, "HTTP authorization check failed", err)
		return
	}

	c.JSON(http.StatusOK, httpCheckResponse(result, matchedPrincipals, subjectAttributesForResult(result, subjectPolicies)))
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
		replyBadRequest(c, err)
		return
	}

	if err := ctrl.validateEntityNamespace(req.Namespace, req.SchemaName, req.EntityType); err != nil {
		replyBadRequest(c, err)
		return
	}

	reqCtx := enrichContextByAuthMaterial(c.Request.Context(), req.AuthType, req.AuthMaterial)
	c.Request = c.Request.WithContext(reqCtx)

	policies, matchedPrincipals, err := ctrl.resolver.Resolve(reqCtx, req.AuthMaterial, req.AuthType)
	if err != nil {
		if errors.Is(err, service.ErrNoMatch) {
			c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
				Error:   "Authentication failed",
				Details: map[string]string{"reason": "No matching principals found"},
			})
			return
		}
		replyInternalError(c, "Failed to resolve principals", err)
		return
	}

	reqCtx = enrichContextWithMatchedPrincipals(reqCtx, matchedPrincipals)
	c.Request = c.Request.WithContext(reqCtx)

	filterSQL, err := ctrl.engine.GetListFilter(reqCtx, policies, req.Namespace, req.SchemaName, req.EntityType)
	if err != nil {
		replyInternalError(c, "Failed to generate filter", err)
		return
	}

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

func validateHTTPCheckRequest(req dto.HTTPAuthzCheckRequestDetails) error {
	if strings.TrimSpace(req.Method) == "" {
		return fmt.Errorf("request.method is required")
	}
	if strings.TrimSpace(req.Path) == "" {
		return fmt.Errorf("request.path is required")
	}
	return nil
}

func toEngineHTTPCheckRequest(req dto.HTTPAuthzCheckRequestDetails, subjects []engine.SubjectPolicySet) engine.HTTPCheckRequest {
	return engine.HTTPCheckRequest{
		Method:   strings.ToUpper(strings.TrimSpace(req.Method)),
		Path:     strings.TrimSpace(req.Path),
		RawQuery: strings.TrimPrefix(strings.TrimSpace(req.RawQuery), "?"),
		Headers:  normalizeHTTPCheckHeaders(req.Headers),
		Body:     []byte(req.Body),
		Subjects: subjects,
	}
}

func normalizeHTTPCheckHeaders(headers map[string]string) map[string]string {
	normalized := make(map[string]string, len(headers))
	for key, value := range headers {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		normalized[strings.ToLower(key)] = value
	}
	return normalized
}

func copySubjectAttributes(attributes map[string]string) map[string]string {
	out := make(map[string]string, len(attributes))
	for key, value := range attributes {
		if strings.TrimSpace(key) == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func subjectAttributesForResult(result engine.HTTPCheckResult, subjects []engine.SubjectPolicySet) map[string]string {
	if result.MatchedPrincipalID != "" {
		for _, subject := range subjects {
			if subject.Subject.PrincipalID == result.MatchedPrincipalID {
				return copySubjectAttributes(subject.Subject.Attributes)
			}
		}
	}
	if len(subjects) == 1 {
		return copySubjectAttributes(subjects[0].Subject.Attributes)
	}
	return map[string]string{}
}

func httpCheckResponse(result engine.HTTPCheckResult, matchedPrincipals []string, subjectAttributes map[string]string) dto.HTTPAuthzCheckResponse {
	reason := "no http_rule grants access to this route"
	if result.Allowed {
		reason = "http_rule grants access to this route"
	}
	return dto.HTTPAuthzCheckResponse{
		Allowed:            result.Allowed,
		MatchedPrincipalID: result.MatchedPrincipalID,
		MatchedPrincipals:  matchedPrincipals,
		MatchedPolicyID:    result.MatchedPolicyID,
		MatchedAction:      result.MatchedAction,
		SubjectAttributes:  copySubjectAttributes(subjectAttributes),
		Reason:             reason,
	}
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
func resolveEntityKey(schemas *engine.SchemaRegistry, schemaName, entityType string, key dto.FlexEntityKey) (map[string]string, error) {
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

// enrichContextByPrincipalID stores a known principal ID into the context so that
// helpers.ConfigureLogger picks it up in every downstream log entry.
func enrichContextByPrincipalID(ctx context.Context, principalID string) context.Context {
	ctx = context.WithValue(ctx, lamassu.LamassuContextKeyAuthType, "principal-id")
	ctx = context.WithValue(ctx, lamassu.LamassuContextKeyAuthID, principalID)
	return ctx
}

// enrichContextByAuthMaterial stores the credential type and material into the context
// before principals are matched, so that even failed-match logs carry auth context.
// For JWT-based auth types (oidc), the raw token is never stored; decoded claims are
// logged instead. X.509 and other credential types are stored as-is.
func enrichContextByAuthMaterial(ctx context.Context, authType string, authMaterial interface{}) context.Context {
	ctx = context.WithValue(ctx, lamassu.LamassuContextKeyAuthType, authType)

	credential := authMaterial
	if authType == "oidc" {
		if tokenStr, ok := authMaterial.(string); ok {
			if claims, err := decodeJWTPayload(tokenStr); err == nil {
				credential = claims
			}
		}
	}

	ctx = context.WithValue(ctx, lamassu.LamassuContextKeyAuthContext, map[string]interface{}{
		"credential": credential,
	})
	return ctx
}

// enrichContextWithMatchedPrincipals adds the resolved principal IDs to the context
// after a successful match, so downstream logs show who was authenticated.
func enrichContextWithMatchedPrincipals(ctx context.Context, principalIDs []string) context.Context {
	return context.WithValue(ctx, lamassu.LamassuContextKeyAuthID, strings.Join(principalIDs, ","))
}
