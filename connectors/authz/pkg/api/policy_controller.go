package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/authz"
)

type PolicyController struct {
	policyManager    *authz.PolicyManager
	principalManager *authz.PrincipalManager
}

func NewPolicyController(policyManager *authz.PolicyManager, principalManager *authz.PrincipalManager) *PolicyController {
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
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
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
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to create policy",
			Details: map[string]string{"error": err.Error()},
		})
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
		if err.Error() == "policy not found: "+policyID {
			c.JSON(http.StatusNotFound, dto.ErrorResponse{
				Error:   "Policy not found",
				Details: map[string]string{"policyId": policyID},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to get policy",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, dto.ToPolicyResponse(policy))
}

// ListPolicies godoc
// @Summary List all policies
// @Description Retrieves all policies
// @Tags policies
// @Produce json
// @Success 200 {object} dto.PolicyListResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/policies [get]
func (ctrl *PolicyController) ListPolicies(c *gin.Context) {
	policies, err := ctrl.policyManager.ListPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to list policies",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, dto.ToPolicyListResponse(policies))
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
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	// Get existing policy
	policy, err := ctrl.policyManager.GetPolicy(c.Request.Context(), policyID)
	if err != nil {
		if err.Error() == "policy not found: "+policyID {
			c.JSON(http.StatusNotFound, dto.ErrorResponse{
				Error:   "Policy not found",
				Details: map[string]string{"policyId": policyID},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to get policy",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	// Apply updates
	req.ApplyToPolicy(policy)

	// Save updated policy
	if err := ctrl.policyManager.UpdatePolicy(c.Request.Context(), policy); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to update policy",
			Details: map[string]string{"error": err.Error()},
		})
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

	// Check if any principals have this policy
	count, err := ctrl.principalManager.CountPolicyPrincipals(policyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to check policy usage",
			Details: map[string]string{"error": err.Error()},
		})
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

	// Delete the policy
	if err := ctrl.policyManager.DeletePolicy(c.Request.Context(), policyID); err != nil {
		if err.Error() == "policy not found: "+policyID {
			c.JSON(http.StatusNotFound, dto.ErrorResponse{
				Error:   "Policy not found",
				Details: map[string]string{"policyId": policyID},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to delete policy",
			Details: map[string]string{"error": err.Error()},
		})
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

	stats, err := ctrl.policyManager.GetPolicyStats(c.Request.Context(), policyID, ctrl.principalManager)
	if err != nil {
		if err.Error() == "policy not found: "+policyID {
			c.JSON(http.StatusNotFound, dto.ErrorResponse{
				Error:   "Policy not found",
				Details: map[string]string{"policyId": policyID},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to get policy stats",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	response := &dto.PolicyStatsResponse{
		ID:             stats.ID,
		Name:           stats.Name,
		RuleCount:      stats.RuleCount,
		PrincipalCount: stats.PrincipalCount,
		SizeBytes:      stats.SizeBytes,
	}

	if !stats.LastModified.IsZero() {
		response.LastModified = stats.LastModified.Format("2006-01-02T15:04:05Z07:00")
	}

	c.JSON(http.StatusOK, response)
}
