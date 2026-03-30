package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/authz"
	"github.com/lamassuiot/authz/pkg/models"
)

type PrincipalController struct {
	manager *authz.PrincipalManager
}

func NewPrincipalController(manager *authz.PrincipalManager) *PrincipalController {
	return &PrincipalController{manager: manager}
}

// CreatePrincipal godoc
// @Summary Create principal
// @Description Create a new principal
// @Tags principals
// @Accept json
// @Produce json
// @Param request body dto.CreatePrincipalRequest true "Principal data"
// @Success 201 {object} dto.PrincipalResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/principals [post]
func (ctrl *PrincipalController) CreatePrincipal(c *gin.Context) {
	var req dto.CreatePrincipalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	principal := &models.Principal{
		ID:         req.ID,
		Name:       req.Name,
		Type:       req.Type,
		AuthConfig: *req.AuthConfig,
		Active:     active,
	}
	if req.Description != nil {
		principal.Description = *req.Description
	}

	if err := ctrl.manager.CreatePrincipal(principal); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to create principal",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusCreated, ctrl.toPrincipalResponse(principal))
}

// GetPrincipal godoc
// @Summary Get principal
// @Description Get a principal by ID
// @Tags principals
// @Produce json
// @Param id path string true "Principal ID"
// @Success 200 {object} dto.PrincipalResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/principals/{id} [get]
func (ctrl *PrincipalController) GetPrincipal(c *gin.Context) {
	id := c.Param("id")

	principal, err := ctrl.manager.GetPrincipal(id)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:   "Principal not found",
			Details: map[string]string{"id": id},
		})
		return
	}

	c.JSON(http.StatusOK, ctrl.toPrincipalResponse(principal))
}

// ListPrincipals godoc
// @Summary List principals
// @Description Get all principals
// @Tags principals
// @Produce json
// @Param activeOnly query bool false "Filter active only"
// @Success 200 {object} dto.ListPrincipalsResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/principals [get]
func (ctrl *PrincipalController) ListPrincipals(c *gin.Context) {
	activeOnly := c.Query("activeOnly") == "true"

	principals, err := ctrl.manager.ListPrincipals(activeOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to list principals",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	responses := make([]dto.PrincipalResponse, len(principals))
	for i, p := range principals {
		responses[i] = ctrl.toPrincipalResponse(p)
	}

	c.JSON(http.StatusOK, dto.ListPrincipalsResponse{
		Principals: responses,
	})
}

// UpdatePrincipal godoc
// @Summary Update principal
// @Description Update a principal
// @Tags principals
// @Accept json
// @Produce json
// @Param id path string true "Principal ID"
// @Param request body dto.UpdatePrincipalRequest true "Update data"
// @Success 200 {object} dto.PrincipalResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/principals/{id] [put]
func (ctrl *PrincipalController) UpdatePrincipal(c *gin.Context) {
	id := c.Param("id")

	var req dto.UpdatePrincipalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	principal, err := ctrl.manager.GetPrincipal(id)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:   "Principal not found",
			Details: map[string]string{"id": id},
		})
		return
	}

	// Apply updates
	if req.Name != nil {
		principal.Name = *req.Name
	}
	if req.Description != nil {
		principal.Description = *req.Description
	}

	if req.AuthConfig != nil {
		principal.AuthConfig = *req.AuthConfig
	}
	if req.Active != nil {
		principal.Active = *req.Active
	}

	// Update principal
	if err := ctrl.manager.UpdatePrincipal(principal); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to update principal",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, ctrl.toPrincipalResponse(principal))
}

// DeletePrincipal godoc
// @Summary Delete principal
// @Description Delete a principal
// @Tags principals
// @Param id path string true "Principal ID"
// @Success 200 {object} "OK"
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/principals/{id} [delete]
func (ctrl *PrincipalController) DeletePrincipal(c *gin.Context) {
	id := c.Param("id")

	if err := ctrl.manager.DeletePrincipal(id); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to delete principal",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// GrantPolicy godoc
// @Summary Grant policy to principal
// @Description Assign a policy to a principal
// @Tags principals
// @Accept json
// @Produce json
// @Param id path string true "Principal ID"
// @Param request body dto.GrantPolicyRequest true "Policy grant data"
// @Success 200 {object} dto.SuccessResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/principals/{id}/policies [post]
func (ctrl *PrincipalController) GrantPolicy(c *gin.Context) {
	id := c.Param("id")

	var req dto.GrantPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Details: map[string]string{"validation": err.Error()},
		})
		return
	}

	if err := ctrl.manager.GrantPolicy(id, req.PolicyID, req.GrantedBy); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to grant policy",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, dto.SuccessResponse{
		Message: "Policy granted successfully",
	})
}

// RevokePolicy godoc
// @Summary Revoke policy from principal
// @Description Remove a policy from a principal
// @Tags principals
// @Param id path string true "Principal ID"
// @Param policyId path string true "Policy ID"
// @Success 200 {object} "OK"
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/principals/{id}/policies/{policyId} [delete]
func (ctrl *PrincipalController) RevokePolicy(c *gin.Context) {
	principalID := c.Param("id")
	policyID := c.Param("policyId")

	if err := ctrl.manager.RevokePolicy(principalID, policyID); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to revoke policy",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetPrincipalPolicies godoc
// @Summary Get principal policies
// @Description Get all policies assigned to a principal
// @Tags principals
// @Produce json
// @Param id path string true "Principal ID"
// @Success 200 {object} dto.ListPrincipalPoliciesResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/principals/{id}/policies [get]
func (ctrl *PrincipalController) GetPrincipalPolicies(c *gin.Context) {
	id := c.Param("id")

	policyIDs, err := ctrl.manager.GetPrincipalPolicies(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to get policies",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	// Convert to response format
	policies := make([]dto.PrincipalPolicyResponse, len(policyIDs))
	for i, policyID := range policyIDs {
		policies[i] = dto.PrincipalPolicyResponse{
			PrincipalID: id,
			PolicyID:    policyID,
			// TODO: Fetch additional details if needed
		}
	}

	c.JSON(http.StatusOK, dto.ListPrincipalPoliciesResponse{
		PrincipalID: id,
		Policies:    policies,
	})
}

// Helper function
func (ctrl *PrincipalController) toPrincipalResponse(p *models.Principal) dto.PrincipalResponse {
	return dto.PrincipalResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Type:        p.Type,
		AuthConfig:  &p.AuthConfig,
		Active:      p.Active,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}
