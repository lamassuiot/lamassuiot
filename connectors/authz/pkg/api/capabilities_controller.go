package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/authz"
)

// CapabilitiesController handles capability-related endpoints.
type CapabilitiesController struct {
	engine           *authz.Engine
	principalManager *authz.PrincipalManager
	policyManager    *authz.PolicyManager
	resolver         *authz.IdentityResolver
}

// NewCapabilitiesController creates a new CapabilitiesController.
func NewCapabilitiesController(
	engine *authz.Engine,
	principalManager *authz.PrincipalManager,
	policyManager *authz.PolicyManager,
	resolver *authz.IdentityResolver,
) *CapabilitiesController {
	return &CapabilitiesController{
		engine:           engine,
		principalManager: principalManager,
		policyManager:    policyManager,
		resolver:         resolver,
	}
}

// GetGlobalCapabilities returns all global actions granted to a known principal, grouped by
// entity type.  Atomic actions are never included.
//
// @Summary      Get global capabilities for a principal
// @Description  Returns all global actions (create, list, …) the principal is granted, keyed
//
// by entity type.  Atomic actions are excluded.
//
// @Tags         capabilities
// @Accept       json
// @Produce      json
// @Param        request body     dto.GetGlobalCapabilitiesRequest true "Principal ID"
// @Success      200 {object}    dto.GlobalCapabilitiesResponse
// @Failure      400 {object}    dto.ErrorResponse
// @Failure      500 {object}    dto.ErrorResponse
// @Router       /api/v1/authz/capabilities/global [post]
func (c *CapabilitiesController) GetGlobalCapabilities(ctx *gin.Context) {
	var req dto.GetGlobalCapabilitiesRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	log.Printf("[API] GetGlobalCapabilities principal=%s", req.PrincipalID)

	gc, err := c.engine.GetGlobalCapabilitiesForPrincipal(
		c.principalManager, c.policyManager, req.PrincipalID,
	)
	if err != nil {
		log.Printf("[API] GetGlobalCapabilities error: %v", err)
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get global capabilities: " + err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, dto.GlobalCapabilitiesResponse{
		GlobalActions: gc,
	})
}

// MatchAndGetGlobalCapabilities matches principals from auth material and returns their
// combined global capabilities (OR logic across matched principals).
//
// @Summary      Match principal and get global capabilities
// @Description  Matches auth material to principals, then returns merged global capabilities.
// @Tags         capabilities
// @Accept       json
// @Produce      json
// @Param        request body     dto.MatchAndGetGlobalCapabilitiesRequest true "Auth material"
// @Success      200 {object}    dto.GlobalCapabilitiesResponse
// @Failure      400 {object}    dto.ErrorResponse
// @Failure      401 {object}    dto.ErrorResponse
// @Failure      500 {object}    dto.ErrorResponse
// @Router       /api/v1/authz/match/capabilities/global [post]
func (c *CapabilitiesController) MatchAndGetGlobalCapabilities(ctx *gin.Context) {
	var req dto.MatchAndGetGlobalCapabilitiesRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	log.Printf("[API] MatchAndGetGlobalCapabilities auth_type=%s", req.AuthType)

	matchedPrincipals, err := c.resolver.MatchPrincipals(ctx.Request.Context(), req.AuthMaterial, req.AuthType)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to match principals: " + err.Error()})
		return
	}
	if len(matchedPrincipals) == 0 {
		ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "No matching principals found"})
		return
	}

	merged := make(authz.GlobalCapabilities)
	for _, principalID := range matchedPrincipals {
		gc, err := c.engine.GetGlobalCapabilitiesForPrincipal(
			c.principalManager, c.policyManager, principalID,
		)
		if err != nil {
			log.Printf("[API] GetGlobalCapabilities error for principal %s: %v", principalID, err)
			ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get global capabilities: " + err.Error()})
			return
		}
		authz.MergeGlobalCapabilities(merged, gc)
	}

	ctx.JSON(http.StatusOK, dto.GlobalCapabilitiesResponse{
		GlobalActions:     merged,
		MatchedPrincipals: matchedPrincipals,
	})
}

// GetEntityCapabilities returns the atomic actions granted to a known principal on one or
// more entity instances in a single call.  Global actions are never included.
//
// @Summary      Get entity capabilities for a principal (batch)
// @Description  Evaluates a list of entity queries for a known principal and returns the
//
//	atomic actions granted on each entity.  Results are in the same order as
//	the input queries.  Global actions are excluded.
//
// @Tags         capabilities
// @Accept       json
// @Produce      json
// @Param        request body     dto.GetEntityCapabilitiesRequest true "Principal + queries"
// @Success      200 {object}    dto.EntityCapabilitiesResponse
// @Failure      400 {object}    dto.ErrorResponse
// @Failure      500 {object}    dto.ErrorResponse
// @Router       /api/v1/authz/capabilities/entity [post]
func (c *CapabilitiesController) GetEntityCapabilities(ctx *gin.Context) {
	var req dto.GetEntityCapabilitiesRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	log.Printf("[API] GetEntityCapabilities principal=%s queries=%d", req.PrincipalID, len(req.Queries))

	engineQueries, err := dtoQueriesToEngine(c.engine.GetSchemas(), req.Queries)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid entity key: " + err.Error()})
		return
	}
	results, err := c.engine.GetEntityCapabilitiesBatchForPrincipal(
		c.principalManager, c.policyManager, req.PrincipalID, engineQueries,
	)
	if err != nil {
		log.Printf("[API] GetEntityCapabilities error: %v", err)
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get entity capabilities: " + err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, dto.EntityCapabilitiesResponse{
		Results: engineResultsToDTO(results),
	})
}

// MatchAndGetEntityCapabilities matches principals from auth material and returns the union
// of atomic actions for each queried entity across all matched principals (OR logic).
//
// @Summary      Match principal and get entity capabilities (batch)
// @Description  Matches auth material to principals, then returns merged atomic actions for
//
//	each entity in the batch.  Global actions are excluded.
//
// @Tags         capabilities
// @Accept       json
// @Produce      json
// @Param        request body     dto.MatchAndGetEntityCapabilitiesRequest true "Auth + queries"
// @Success      200 {object}    dto.EntityCapabilitiesResponse
// @Failure      400 {object}    dto.ErrorResponse
// @Failure      401 {object}    dto.ErrorResponse
// @Failure      500 {object}    dto.ErrorResponse
// @Router       /api/v1/authz/match/capabilities/entity [post]
func (c *CapabilitiesController) MatchAndGetEntityCapabilities(ctx *gin.Context) {
	var req dto.MatchAndGetEntityCapabilitiesRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	log.Printf("[API] MatchAndGetEntityCapabilities auth_type=%s queries=%d", req.AuthType, len(req.Queries))

	matchedPrincipals, err := c.resolver.MatchPrincipals(ctx.Request.Context(), req.AuthMaterial, req.AuthType)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to match principals: " + err.Error()})
		return
	}
	if len(matchedPrincipals) == 0 {
		ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "No matching principals found"})
		return
	}

	engineQueries, err := dtoQueriesToEngine(c.engine.GetSchemas(), req.Queries)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid entity key: " + err.Error()})
		return
	}

	// Merge results across all matched principals with OR logic (position-aligned).
	merged := make([]authz.EntityCapabilitiesResult, len(engineQueries))
	for i, q := range engineQueries {
		merged[i] = authz.EntityCapabilitiesResult{
			EntityCapabilities: authz.EntityCapabilities{
				Namespace:  q.Namespace,
				SchemaName: q.SchemaName,
				EntityType: q.EntityType,
				EntityKey:  q.EntityKey,
				Actions:    []string{},
			},
		}
	}

	for _, principalID := range matchedPrincipals {
		batch, err := c.engine.GetEntityCapabilitiesBatchForPrincipal(
			c.principalManager, c.policyManager, principalID, engineQueries,
		)
		if err != nil {
			log.Printf("[API] GetEntityCapabilities batch error for principal %s: %v", principalID, err)
			ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get entity capabilities: " + err.Error()})
			return
		}
		for i, r := range batch {
			if r.Error != "" {
				// Preserve the error only if this position has no successful actions yet.
				if len(merged[i].Actions) == 0 && merged[i].Error == "" {
					merged[i].Error = r.Error
				}
				continue
			}
			// Clear any prior error once at least one principal succeeds.
			merged[i].Error = ""
			actionSet := make(map[string]bool)
			for _, a := range merged[i].Actions {
				actionSet[a] = true
			}
			for _, a := range r.Actions {
				if !actionSet[a] {
					merged[i].Actions = append(merged[i].Actions, a)
					actionSet[a] = true
				}
			}
		}
	}

	ctx.JSON(http.StatusOK, dto.EntityCapabilitiesResponse{
		Results:           engineResultsToDTO(merged),
		MatchedPrincipals: matchedPrincipals,
	})
}

// dtoQueriesToEngine converts DTO query slice to engine query slice, resolving any
// plain-string entity keys against the schema registry.
func dtoQueriesToEngine(schemas *authz.SchemaRegistry, qs []dto.EntityCapabilityQuery) ([]authz.EntityCapabilityQuery, error) {
	out := make([]authz.EntityCapabilityQuery, len(qs))
	for i, q := range qs {
		key, err := resolveEntityKey(schemas, q.SchemaName, q.EntityType, q.EntityKey)
		if err != nil {
			return nil, fmt.Errorf("query %d: %w", i, err)
		}
		out[i] = authz.EntityCapabilityQuery{
			Namespace:  q.Namespace,
			SchemaName: q.SchemaName,
			EntityType: q.EntityType,
			EntityKey:  key,
		}
	}
	return out, nil
}

// engineResultsToDTO converts engine result slice to DTO result slice.
func engineResultsToDTO(rs []authz.EntityCapabilitiesResult) []dto.EntityCapabilitiesResultDTO {
	out := make([]dto.EntityCapabilitiesResultDTO, len(rs))
	for i, r := range rs {
		out[i] = dto.EntityCapabilitiesResultDTO{
			Namespace:  r.Namespace,
			SchemaName: r.SchemaName,
			EntityType: r.EntityType,
			EntityKey:  r.EntityKey,
			Actions:    r.Actions,
			Error:      r.Error,
		}
	}
	return out
}
