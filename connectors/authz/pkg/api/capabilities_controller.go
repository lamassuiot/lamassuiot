package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/api/dto"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/engine"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/service"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

// CapabilitiesController handles capability-related endpoints.
type CapabilitiesController struct {
	eng              *engine.Engine
	principalManager service.PrincipalService
	policyManager    service.PolicyService
	resolver         *service.IdentityResolver
	logger           *logrus.Entry
}

// NewCapabilitiesController creates a new CapabilitiesController.
func NewCapabilitiesController(
	eng *engine.Engine,
	principalManager service.PrincipalService,
	policyManager service.PolicyService,
	resolver *service.IdentityResolver,
	logger *logrus.Entry,
) *CapabilitiesController {
	return &CapabilitiesController{
		eng:              eng,
		principalManager: principalManager,
		policyManager:    policyManager,
		resolver:         resolver,
		logger:           logger,
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

	log := helpers.ConfigureLogger(ctx.Request.Context(), c.logger)
	log.WithFields(logrus.Fields{"principal_id": req.PrincipalID}).Debug("get global capabilities")

	gc, err := service.GetGlobalCapabilitiesForPrincipal(
		ctx.Request.Context(), c.eng, c.principalManager, c.policyManager, req.PrincipalID,
	)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err}).Error("get global capabilities failed")
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

	log := helpers.ConfigureLogger(ctx.Request.Context(), c.logger)
	log.WithFields(logrus.Fields{"auth_type": req.AuthType}).Debug("match and get global capabilities")

	matchedPrincipals, err := c.resolver.MatchPrincipals(ctx.Request.Context(), req.AuthMaterial, req.AuthType)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to match principals: " + err.Error()})
		return
	}
	if len(matchedPrincipals) == 0 {
		ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "No matching principals found"})
		return
	}

	merged := make(engine.GlobalCapabilities)
	for _, principalID := range matchedPrincipals {
		gc, err := service.GetGlobalCapabilitiesForPrincipal(
			ctx.Request.Context(), c.eng, c.principalManager, c.policyManager, principalID,
		)
		if err != nil {
			log.WithFields(logrus.Fields{"principal_id": principalID, "error": err}).Error("get global capabilities failed")
			ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get global capabilities: " + err.Error()})
			return
		}
		engine.MergeGlobalCapabilities(merged, gc)
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

	log := helpers.ConfigureLogger(ctx.Request.Context(), c.logger)
	log.WithFields(logrus.Fields{"principal_id": req.PrincipalID, "query_count": len(req.Queries)}).Debug("get entity capabilities")

	engineQueries, err := dtoQueriesToEngine(c.eng.GetSchemas(), req.Queries)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid entity key: " + err.Error()})
		return
	}
	results, err := service.GetEntityCapabilitiesBatchForPrincipal(
		ctx.Request.Context(), c.eng, c.principalManager, c.policyManager, req.PrincipalID, engineQueries,
	)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err}).Error("get entity capabilities failed")
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

	log := helpers.ConfigureLogger(ctx.Request.Context(), c.logger)
	log.WithFields(logrus.Fields{"auth_type": req.AuthType, "query_count": len(req.Queries)}).Debug("match and get entity capabilities")

	matchedPrincipals, err := c.resolver.MatchPrincipals(ctx.Request.Context(), req.AuthMaterial, req.AuthType)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to match principals: " + err.Error()})
		return
	}
	if len(matchedPrincipals) == 0 {
		ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "No matching principals found"})
		return
	}

	engineQueries, err := dtoQueriesToEngine(c.eng.GetSchemas(), req.Queries)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid entity key: " + err.Error()})
		return
	}

	// Merge results across all matched principals with OR logic (position-aligned).
	merged := make([]engine.EntityCapabilitiesResult, len(engineQueries))
	for i, q := range engineQueries {
		merged[i] = engine.EntityCapabilitiesResult{
			EntityCapabilities: engine.EntityCapabilities{
				Namespace:  q.Namespace,
				SchemaName: q.SchemaName,
				EntityType: q.EntityType,
				EntityKey:  q.EntityKey,
				Actions:    []string{},
			},
		}
	}

	for _, principalID := range matchedPrincipals {
		batch, err := service.GetEntityCapabilitiesBatchForPrincipal(
			ctx.Request.Context(), c.eng, c.principalManager, c.policyManager, principalID, engineQueries,
		)
		if err != nil {
			log.WithFields(logrus.Fields{"principal_id": principalID, "error": err}).Error("get entity capabilities batch failed")
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
func dtoQueriesToEngine(schemas *engine.SchemaRegistry, qs []dto.EntityCapabilityQuery) ([]engine.EntityCapabilityQuery, error) {
	out := make([]engine.EntityCapabilityQuery, len(qs))
	for i, q := range qs {
		key, err := resolveEntityKey(schemas, q.SchemaName, q.EntityType, q.EntityKey)
		if err != nil {
			return nil, fmt.Errorf("query %d: %w", i, err)
		}
		out[i] = engine.EntityCapabilityQuery{
			Namespace:  q.Namespace,
			SchemaName: q.SchemaName,
			EntityType: q.EntityType,
			EntityKey:  key,
		}
	}
	return out, nil
}

// engineResultsToDTO converts engine result slice to DTO result slice.
func engineResultsToDTO(rs []engine.EntityCapabilitiesResult) []dto.EntityCapabilitiesResultDTO {
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
