package controllers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

type TenantManagerHttpRoutes struct {
	svc    *services.TenantManagerService
	logger *logrus.Entry
}

func NewTenantManagerHttpRoutes(logger *logrus.Entry, svc *services.TenantManagerService) *TenantManagerHttpRoutes {
	return &TenantManagerHttpRoutes{svc: svc, logger: logger}
}

type identityBody struct {
	Issuer  string `json:"issuer" binding:"required"`
	Subject string `json:"subject" binding:"required"`
}

type createOrganizationBody struct {
	Name string `json:"name" binding:"required"`
}

type createTenantBody struct {
	OrganizationID string               `json:"organization_id" binding:"required"`
	Name           string               `json:"name" binding:"required"`
	IsolationMode  models.IsolationMode `json:"isolation_mode"`
	InitialAdmin   identityBody         `json:"initial_admin" binding:"required"`
}

type tenantStatusBody struct {
	Status models.TenantStatus `json:"status" binding:"required"`
}

type assignMembershipBody struct {
	Issuer  string            `json:"issuer" binding:"required"`
	Subject string            `json:"subject" binding:"required"`
	Role    models.TenantRole `json:"role" binding:"required"`
}

type updateMembershipBody struct {
	Role   *models.TenantRole       `json:"role"`
	Status *models.MembershipStatus `json:"status"`
}

type createInvitationBody struct {
	Role           models.TenantRole `json:"role" binding:"required"`
	ExpiresInHours int               `json:"expires_in_hours"`
}

func (r *TenantManagerHttpRoutes) handleError(c *gin.Context, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errs.ErrTenantManagerNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errs.ErrTenantManagerForbidden):
		status = http.StatusForbidden
	case errors.Is(err, errs.ErrTenantManagerValidation):
		status = http.StatusBadRequest
	case errors.Is(err, errs.ErrTenantManagerConflict),
		errors.Is(err, errs.ErrTenantManagerLastTenantAdmin),
		errors.Is(err, errs.ErrTenantManagerSelfModification),
		errors.Is(err, errs.ErrTenantManagerInvalidTransition),
		errors.Is(err, errs.ErrTenantManagerInvalidInvitation):
		status = http.StatusConflict
	}
	if status == http.StatusInternalServerError {
		r.logger.WithError(err).Error("tenant management request failed")
		c.JSON(status, gin.H{"err": "internal error"})
		return
	}
	c.JSON(status, gin.H{"err": err.Error()})
}

// actor returns the caller identity: the one validated by the tenant context
// middleware on tenant routes, or the validated JWT identity otherwise.
func actor(c *gin.Context) (services.TenantManagerActor, bool) {
	identity, err := tenantcontext.AuthenticatedIdentityFromContext(c.Request.Context())
	correlationID := c.GetHeader(models.HttpRequestIDHeader)
	if tenantContext, ctxErr := core.RequireTenantContext(c.Request.Context()); ctxErr == nil {
		correlationID = tenantContext.CorrelationID
	}
	if err != nil {
		identity, err = tenantcontext.JWTIdentityProvider(c.Request.Context())
	}
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"err": "authenticated identity is required"})
		return services.TenantManagerActor{}, false
	}
	return services.TenantManagerActor{Issuer: identity.Issuer, Subject: identity.Subject, CorrelationID: correlationID}, true
}

func scopedTenantID(c *gin.Context) (string, bool) {
	tenantContext, err := core.RequireTenantContext(c.Request.Context())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"err": "tenant context is required"})
		return "", false
	}
	return tenantContext.TenantID, true
}

func (r *TenantManagerHttpRoutes) MyMemberships(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	memberships, err := r.svc.MyMemberships(c.Request.Context(), caller)
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"memberships": memberships})
}

func (r *TenantManagerHttpRoutes) AcceptInvitation(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	membership, err := r.svc.AcceptInvitation(c.Request.Context(), caller, c.Param("code"))
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, membership)
}

func (r *TenantManagerHttpRoutes) CreateOrganization(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	var body createOrganizationBody
	if err := c.ShouldBindJSON(&body); err != nil {
		r.handleError(c, errs.ErrTenantManagerValidation)
		return
	}
	organization, err := r.svc.CreateOrganization(c.Request.Context(), caller, body.Name)
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, organization)
}

func (r *TenantManagerHttpRoutes) ListOrganizations(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	organizations, err := r.svc.ListOrganizations(c.Request.Context(), caller)
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"organizations": organizations})
}

func (r *TenantManagerHttpRoutes) CreateTenant(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	var body createTenantBody
	if err := c.ShouldBindJSON(&body); err != nil {
		r.handleError(c, errs.ErrTenantManagerValidation)
		return
	}
	tenant, err := r.svc.CreateTenant(c.Request.Context(), caller, services.CreateTenantInput{
		OrganizationID: body.OrganizationID,
		Name:           body.Name,
		IsolationMode:  body.IsolationMode,
		Admin:          services.TenantManagerIdentity{Issuer: body.InitialAdmin.Issuer, Subject: body.InitialAdmin.Subject},
	})
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, tenant)
}

func (r *TenantManagerHttpRoutes) ListTenants(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	tenants, err := r.svc.ListTenants(c.Request.Context(), caller, c.Query("organization_id"))
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenants": tenants})
}

func (r *TenantManagerHttpRoutes) SetTenantStatus(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	var body tenantStatusBody
	if err := c.ShouldBindJSON(&body); err != nil {
		r.handleError(c, errs.ErrTenantManagerValidation)
		return
	}
	tenant, err := r.svc.SetTenantStatus(c.Request.Context(), caller, c.Param("tenantId"), body.Status)
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, tenant)
}

func (r *TenantManagerHttpRoutes) ListMemberships(c *gin.Context) {
	tenantID, ok := scopedTenantID(c)
	if !ok {
		return
	}
	memberships, err := r.svc.ListMemberships(c.Request.Context(), tenantID)
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"memberships": memberships})
}

func (r *TenantManagerHttpRoutes) AssignMembership(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	tenantID, ok := scopedTenantID(c)
	if !ok {
		return
	}
	var body assignMembershipBody
	if err := c.ShouldBindJSON(&body); err != nil {
		r.handleError(c, errs.ErrTenantManagerValidation)
		return
	}
	membership, err := r.svc.AssignMembership(c.Request.Context(), caller, tenantID,
		services.TenantManagerIdentity{Issuer: body.Issuer, Subject: body.Subject}, body.Role)
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, membership)
}

func (r *TenantManagerHttpRoutes) UpdateMembership(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	tenantID, ok := scopedTenantID(c)
	if !ok {
		return
	}
	var body updateMembershipBody
	if err := c.ShouldBindJSON(&body); err != nil {
		r.handleError(c, errs.ErrTenantManagerValidation)
		return
	}
	membership, err := r.svc.UpdateMembership(c.Request.Context(), caller, tenantID, c.Param("membershipId"),
		models.MembershipUpdate{Role: body.Role, Status: body.Status})
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, membership)
}

func (r *TenantManagerHttpRoutes) RevokeMembership(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	tenantID, ok := scopedTenantID(c)
	if !ok {
		return
	}
	membership, err := r.svc.RevokeMembership(c.Request.Context(), caller, tenantID, c.Param("membershipId"))
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, membership)
}

func (r *TenantManagerHttpRoutes) ListInvitations(c *gin.Context) {
	tenantID, ok := scopedTenantID(c)
	if !ok {
		return
	}
	invitations, err := r.svc.ListInvitations(c.Request.Context(), tenantID)
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"invitations": invitations})
}

func (r *TenantManagerHttpRoutes) CreateInvitation(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	tenantID, ok := scopedTenantID(c)
	if !ok {
		return
	}
	var body createInvitationBody
	if err := c.ShouldBindJSON(&body); err != nil || body.ExpiresInHours < 0 {
		r.handleError(c, errs.ErrTenantManagerValidation)
		return
	}
	invitation, code, err := r.svc.CreateInvitation(c.Request.Context(), caller, tenantID, body.Role,
		time.Duration(body.ExpiresInHours)*time.Hour)
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"invitation": invitation, "code": code})
}

func (r *TenantManagerHttpRoutes) RevokeInvitation(c *gin.Context) {
	caller, ok := actor(c)
	if !ok {
		return
	}
	tenantID, ok := scopedTenantID(c)
	if !ok {
		return
	}
	invitation, err := r.svc.RevokeInvitation(c.Request.Context(), caller, tenantID, c.Param("invitationId"))
	if err != nil {
		r.handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, invitation)
}
