package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/api/dto"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/service"
	"github.com/lamassuiot/lamassuiot/pki/v3/pkg/controllers"
)

type PolicyController struct {
	policyManager    service.PolicyService
	principalManager service.PrincipalService
}

func NewPolicyController(policyManager service.PolicyService, principalManager service.PrincipalService) *PolicyController {
	return &PolicyController{
		policyManager:    policyManager,
		principalManager: principalManager,
	}
}

// CreatePolicy godoc
// @Summary Create a new policy
// @Description Creates a new authorization policy
// @Tags policies
// @Accept json
// @Produce json
// @Param request body dto.CreatePolicyRequest true "Policy creation request"
// @Success 201 {object} dto.PolicyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/policies [post]
func (ctrl *PolicyController) CreatePolicy(c *gin.Context) {
	var req dto.CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		replyBadRequest(c, err)
		return
	}

	policy := req.ToPolicy()

	if err := ctrl.policyManager.CreatePolicy(c.Request.Context(), policy); err != nil {
		if err.Error() == "policy with ID "+policy.ID+" already exists" {
			c.JSON(http.StatusConflict, dto.ErrorResponse{
				Error:   "Policy already exists",
				Details: map[string]string{"policyId": policy.ID},
			})
			return
		}
		replyInternalError(c, "Failed to create policy", err)
		return
	}

	c.JSON(http.StatusCreated, dto.ToPolicyResponse(policy))
}

// GetPolicy godoc
// @Summary Get a policy by ID
// @Description Retrieves a policy by its unique ID
// @Tags policies
// @Produce json
// @Param id path string true "Policy ID"
// @Success 200 {object} dto.PolicyResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/policies/{id} [get]
func (ctrl *PolicyController) GetPolicy(c *gin.Context) {
	policyID := c.Param("id")

	policy, err := ctrl.policyManager.GetPolicy(c.Request.Context(), policyID)
	if err != nil {
		if replyPolicyNotFound(c, err, policyID) {
			return
		}
		replyInternalError(c, "Failed to get policy", err)
		return
	}

	c.JSON(http.StatusOK, dto.ToPolicyResponse(policy))
}

// SearchPolicies godoc
// @Summary Search policies
// @Description Searches policies by ID, Name, or Description (case-insensitive). Returns all policies when query is empty.
// @Tags policies
// @Produce json
// @Param query query string false "Search query"
// @Success 200 {object} dto.PolicyListResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/policies/search [get]
func (ctrl *PolicyController) SearchPolicies(c *gin.Context) {
	query := c.Query("query")

	policies, err := ctrl.policyManager.SearchPolicies(c.Request.Context(), query)
	if err != nil {
		replyInternalError(c, "Failed to search policies", err)
		return
	}

	c.JSON(http.StatusOK, dto.ToPolicyListResponse(policies, ""))
}

// ListPolicies godoc
// @Summary List all policies
// @Description Retrieves all policies
// @Tags policies
// @Produce json
// @Param filter query string false "Filter expression (e.g. name[ct]foo)"
// @Param sort_by query string false "Field to sort by"
// @Param sort_mode query string false "Sort direction: asc or desc"
// @Param page_size query int false "Page size"
// @Param bookmark query string false "Pagination bookmark"
// @Success 200 {object} dto.PolicyListResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/policies [get]
func (ctrl *PolicyController) ListPolicies(c *gin.Context) {
	queryParams, err := controllers.FilterQuery(c.Request, PolicyFilterableFields)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid filter",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	policies, nextBookmark, err := ctrl.policyManager.ListPolicies(c.Request.Context(), queryParams)
	if err != nil {
		replyInternalError(c, "Failed to list policies", err)
		return
	}

	c.JSON(http.StatusOK, dto.ToPolicyListResponse(policies, nextBookmark))
}

// UpdatePolicy godoc
// @Summary Update a policy
// @Description Updates an existing policy
// @Tags policies
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Param request body dto.UpdatePolicyRequest true "Policy update request"
// @Success 200 {object} dto.PolicyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/policies/{id} [put]
func (ctrl *PolicyController) UpdatePolicy(c *gin.Context) {
	policyID := c.Param("id")

	var req dto.UpdatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		replyBadRequest(c, err)
		return
	}

	policy, err := ctrl.policyManager.GetPolicy(c.Request.Context(), policyID)
	if err != nil {
		if replyPolicyNotFound(c, err, policyID) {
			return
		}
		replyInternalError(c, "Failed to get policy", err)
		return
	}

	req.ApplyToPolicy(policy)

	if err := ctrl.policyManager.UpdatePolicy(c.Request.Context(), policy); err != nil {
		replyInternalError(c, "Failed to update policy", err)
		return
	}

	c.JSON(http.StatusOK, dto.ToPolicyResponse(policy))
}

// DeletePolicy godoc
// @Summary Delete a policy
// @Description Deletes a policy by ID
// @Tags policies
// @Param id path string true "Policy ID"
// @Success 200 {object} "OK"
// @Failure 404 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/policies/{id} [delete]
func (ctrl *PolicyController) DeletePolicy(c *gin.Context) {
	policyID := c.Param("id")

	count, err := ctrl.principalManager.CountPolicyPrincipals(c.Request.Context(), policyID)
	if err != nil {
		replyInternalError(c, "Failed to check policy usage", err)
		return
	}

	if count > 0 {
		c.JSON(http.StatusConflict, dto.ErrorResponse{
			Error: "Cannot delete policy in use",
			Details: map[string]string{
				"policyId":       policyID,
				"principalCount": fmt.Sprint(count),
				"message":        "Policy is assigned to principals. Remove policy from all principals before deleting.",
			},
		})
		return
	}

	if err := ctrl.policyManager.DeletePolicy(c.Request.Context(), policyID); err != nil {
		if replyPolicyNotFound(c, err, policyID) {
			return
		}
		if err.Error() == fmt.Sprintf("system-managed policy %q cannot be deleted", policyID) {
			c.JSON(http.StatusForbidden, dto.ErrorResponse{
				Error:   "Cannot delete system-managed policy",
				Details: map[string]string{"policyId": policyID},
			})
			return
		}
		replyInternalError(c, "Failed to delete policy", err)
		return
	}

	c.Status(http.StatusNoContent)
}

// GetPolicyStats godoc
// @Summary Get policy statistics
// @Description Retrieves statistics about a policy
// @Tags policies
// @Produce json
// @Param id path string true "Policy ID"
// @Success 200 {object} dto.PolicyStatsResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/policies/{id}/stats [get]
func (ctrl *PolicyController) GetPolicyStats(c *gin.Context) {
	policyID := c.Param("id")
	ctx := c.Request.Context()

	policy, err := ctrl.policyManager.GetPolicy(ctx, policyID)
	if err != nil {
		if replyPolicyNotFound(c, err, policyID) {
			return
		}
		replyInternalError(c, "Failed to get policy stats", err)
		return
	}

	var principalCount int64
	if ctrl.principalManager != nil {
		principalCount, _ = ctrl.principalManager.CountPolicyPrincipals(ctx, policyID)
	}

	rulesJSON, _ := json.Marshal(policy.Rules)

	c.JSON(http.StatusOK, &dto.PolicyStatsResponse{
		ID:             policy.ID,
		Name:           policy.Name,
		RuleCount:      len(policy.Rules),
		PrincipalCount: principalCount,
		SizeBytes:      int64(len(rulesJSON)),
	})
}
