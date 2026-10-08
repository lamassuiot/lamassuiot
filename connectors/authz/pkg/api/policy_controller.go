package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
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
func (ctrl *PolicyController) CreatePolicy(c *gin.Context) {
	var req dto.CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		replyBadRequest(c, err)
		return
	}

	if service.IsSystemPolicy(req.ID) {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid policy ID",
			Details: map[string]string{
				"policyId": req.ID,
				"message":  fmt.Sprintf("Policy IDs starting with %q are reserved for system-managed policies.", service.SystemPolicyPrefix),
			},
		})
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
		if err.Error() == fmt.Sprintf("system-managed policy %q cannot be updated", policyID) {
			c.JSON(http.StatusForbidden, dto.ErrorResponse{
				Error:   "Cannot update system-managed policy",
				Details: map[string]string{"policyId": policyID},
			})
			return
		}
		replyInternalError(c, "Failed to update policy", err)
		return
	}

	c.JSON(http.StatusOK, dto.ToPolicyResponse(policy))
}

// DeletePolicy godoc
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
