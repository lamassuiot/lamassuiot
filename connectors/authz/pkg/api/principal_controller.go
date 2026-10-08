package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type PrincipalController struct {
	manager service.PrincipalService
}

func NewPrincipalController(manager service.PrincipalService) *PrincipalController {
	return &PrincipalController{manager: manager}
}

// CreatePrincipal godoc
func (ctrl *PrincipalController) CreatePrincipal(c *gin.Context) {
	var req dto.CreatePrincipalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		replyBadRequest(c, err)
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

	if err := ctrl.manager.CreatePrincipal(c.Request.Context(), principal); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to create principal",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusCreated, ctrl.toPrincipalResponse(principal))
}

// GetPrincipal godoc
func (ctrl *PrincipalController) GetPrincipal(c *gin.Context) {
	id := c.Param("id")

	principal, err := ctrl.manager.GetPrincipal(c.Request.Context(), id)
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
func (ctrl *PrincipalController) ListPrincipals(c *gin.Context) {
	queryParams, err := controllers.FilterQuery(c.Request, PrincipalFilterableFields)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid filter",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	principals, nextBookmark, err := ctrl.manager.ListPrincipals(c.Request.Context(), queryParams)
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
		IterableList: resources.IterableList[dto.PrincipalResponse]{
			NextBookmark: nextBookmark,
			List:         responses,
		},
	})
}

// UpdatePrincipal godoc
func (ctrl *PrincipalController) UpdatePrincipal(c *gin.Context) {
	id := c.Param("id")

	var req dto.UpdatePrincipalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		replyBadRequest(c, err)
		return
	}

	principal, err := ctrl.manager.GetPrincipal(c.Request.Context(), id)
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
	if err := ctrl.manager.UpdatePrincipal(c.Request.Context(), principal); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to update principal",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, ctrl.toPrincipalResponse(principal))
}

// DeletePrincipal godoc
func (ctrl *PrincipalController) DeletePrincipal(c *gin.Context) {
	id := c.Param("id")

	if err := ctrl.manager.DeletePrincipal(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to delete principal",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// GrantPolicy godoc
func (ctrl *PrincipalController) GrantPolicy(c *gin.Context) {
	id := c.Param("id")

	var req dto.GrantPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		replyBadRequest(c, err)
		return
	}

	if err := ctrl.manager.GrantPolicy(c.Request.Context(), id, req.PolicyID, req.GrantedBy); err != nil {
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
func (ctrl *PrincipalController) RevokePolicy(c *gin.Context) {
	principalID := c.Param("id")
	policyID := c.Param("policyId")

	if err := ctrl.manager.RevokePolicy(c.Request.Context(), principalID, policyID); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to revoke policy",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetPrincipalPolicies godoc
func (ctrl *PrincipalController) GetPrincipalPolicies(c *gin.Context) {
	id := c.Param("id")

	queryParams, err := controllers.FilterQuery(c.Request, PrincipalPolicyFilterableFields)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid filter",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	grants, nextBookmark, err := ctrl.manager.GetPrincipalPolicies(c.Request.Context(), id, queryParams)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to get policies",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}

	policies := make([]dto.PrincipalPolicyResponse, len(grants))
	for i, g := range grants {
		policies[i] = dto.PrincipalPolicyResponse{
			PrincipalID: id,
			PolicyID:    g.PolicyID,
			GrantedAt:   g.GrantedAt,
			GrantedBy:   g.GrantedBy,
		}
	}

	c.JSON(http.StatusOK, dto.ListPrincipalPoliciesResponse{
		PrincipalID: id,
		IterableList: resources.IterableList[dto.PrincipalPolicyResponse]{
			NextBookmark: nextBookmark,
			List:         policies,
		},
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
