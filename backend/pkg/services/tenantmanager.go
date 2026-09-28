package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

const (
	DefaultInvitationTTL = 72 * time.Hour
	MaxInvitationTTL     = 168 * time.Hour
	maxCatalogNameLength = 128
)

// TenantManagerActor is the authenticated identity performing an operation.
type TenantManagerActor struct {
	Issuer        string
	Subject       string
	CorrelationID string
}

type TenantManagerIdentity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type CreateTenantInput struct {
	OrganizationID string
	Name           string
	IsolationMode  models.IsolationMode
	Admin          TenantManagerIdentity
}

// TenantManagerService manages organizations, tenants, memberships and
// invitations. Provisioners may only manage the catalog; membership
// operations are authorized by the caller's tenant membership before they
// reach this service.
type TenantManagerService struct {
	repo         storage.TenantManagementRepo
	provisioners map[TenantManagerIdentity]struct{}
	logger       *logrus.Entry
	now          func() time.Time
}

func NewTenantManagerService(repo storage.TenantManagementRepo, provisioners []TenantManagerIdentity, logger *logrus.Entry) (*TenantManagerService, error) {
	if repo == nil {
		return nil, fmt.Errorf("tenant management storage is required")
	}
	allowed := make(map[TenantManagerIdentity]struct{}, len(provisioners))
	for _, provisioner := range provisioners {
		if strings.TrimSpace(provisioner.Issuer) == "" || strings.TrimSpace(provisioner.Subject) == "" {
			return nil, fmt.Errorf("provisioner issuer and subject are required")
		}
		allowed[provisioner] = struct{}{}
	}
	return &TenantManagerService{
		repo:         repo,
		provisioners: allowed,
		logger:       logger,
		now:          func() time.Time { return time.Now().UTC() },
	}, nil
}

func (svc *TenantManagerService) audit(actor TenantManagerActor, action string, fields logrus.Fields) {
	entry := svc.logger.WithFields(logrus.Fields{
		"action":         action,
		"actor_issuer":   actor.Issuer,
		"actor_subject":  actor.Subject,
		"correlation_id": actor.CorrelationID,
	})
	entry.WithFields(fields).Info("tenant management change")
}

func (svc *TenantManagerService) requireProvisioner(actor TenantManagerActor) error {
	if _, ok := svc.provisioners[TenantManagerIdentity{Issuer: actor.Issuer, Subject: actor.Subject}]; !ok {
		return errs.ErrTenantManagerForbidden
	}
	return nil
}

func validCatalogName(name string) bool {
	trimmed := strings.TrimSpace(name)
	return trimmed != "" && len(trimmed) <= maxCatalogNameLength
}

func validIdentity(issuer, subject string) bool {
	return strings.TrimSpace(issuer) != "" && strings.TrimSpace(subject) != ""
}

func (svc *TenantManagerService) MyMemberships(ctx context.Context, actor TenantManagerActor) ([]models.MembershipSummary, error) {
	return svc.repo.ListIdentityMemberships(ctx, actor.Issuer, actor.Subject)
}

func (svc *TenantManagerService) CreateOrganization(ctx context.Context, actor TenantManagerActor, name string) (*models.Organization, error) {
	if err := svc.requireProvisioner(actor); err != nil {
		return nil, err
	}
	if !validCatalogName(name) {
		return nil, errs.ErrTenantManagerValidation
	}
	organization := &models.Organization{ID: uuid.NewString(), Name: strings.TrimSpace(name), CreatedAt: svc.now()}
	if err := svc.repo.CreateOrganization(ctx, organization); err != nil {
		return nil, err
	}
	svc.audit(actor, "organization.create", logrus.Fields{"organization_id": organization.ID})
	return organization, nil
}

func (svc *TenantManagerService) ListOrganizations(ctx context.Context, actor TenantManagerActor) ([]models.Organization, error) {
	if err := svc.requireProvisioner(actor); err != nil {
		return nil, err
	}
	return svc.repo.ListOrganizations(ctx)
}

func (svc *TenantManagerService) CreateTenant(ctx context.Context, actor TenantManagerActor, input CreateTenantInput) (*models.Tenant, error) {
	if err := svc.requireProvisioner(actor); err != nil {
		return nil, err
	}
	if input.IsolationMode == "" {
		input.IsolationMode = models.IsolationPooled
	}
	if strings.TrimSpace(input.OrganizationID) == "" || !validCatalogName(input.Name) ||
		!models.IsIsolationMode(input.IsolationMode) || !validIdentity(input.Admin.Issuer, input.Admin.Subject) {
		return nil, errs.ErrTenantManagerValidation
	}
	now := svc.now()
	tenant := &models.Tenant{
		ID:             uuid.NewString(),
		OrganizationID: input.OrganizationID,
		Name:           strings.TrimSpace(input.Name),
		Status:         models.TenantActive,
		IsolationMode:  input.IsolationMode,
		CreatedAt:      now,
	}
	admin := &models.Membership{
		ID:              uuid.NewString(),
		OrganizationID:  tenant.OrganizationID,
		TenantID:        tenant.ID,
		IdentityIssuer:  input.Admin.Issuer,
		IdentitySubject: input.Admin.Subject,
		Role:            models.RoleTenantAdmin,
		Status:          models.MembershipActive,
		CreatedAt:       now,
	}
	if err := svc.repo.CreateTenantWithAdmin(ctx, tenant, admin); err != nil {
		return nil, err
	}
	svc.audit(actor, "tenant.create", logrus.Fields{
		"organization_id": tenant.OrganizationID, "tenant_id": tenant.ID,
		"target_issuer": admin.IdentityIssuer, "target_subject": admin.IdentitySubject, "new_role": admin.Role,
	})
	return tenant, nil
}

func (svc *TenantManagerService) ListTenants(ctx context.Context, actor TenantManagerActor, organizationID string) ([]models.Tenant, error) {
	if err := svc.requireProvisioner(actor); err != nil {
		return nil, err
	}
	return svc.repo.ListTenants(ctx, organizationID)
}

func (svc *TenantManagerService) SetTenantStatus(ctx context.Context, actor TenantManagerActor, tenantID string, status models.TenantStatus) (*models.Tenant, error) {
	if err := svc.requireProvisioner(actor); err != nil {
		return nil, err
	}
	if strings.TrimSpace(tenantID) == "" || status == "" {
		return nil, errs.ErrTenantManagerValidation
	}
	tenant, err := svc.repo.UpdateTenantStatus(ctx, tenantID, status, svc.now())
	if err != nil {
		return nil, err
	}
	svc.audit(actor, "tenant.status", logrus.Fields{"tenant_id": tenantID, "new_status": status})
	return tenant, nil
}

func (svc *TenantManagerService) ListMemberships(ctx context.Context, tenantID string) ([]models.Membership, error) {
	return svc.repo.ListTenantMemberships(ctx, tenantID)
}

func (svc *TenantManagerService) AssignMembership(ctx context.Context, actor TenantManagerActor, tenantID string, target TenantManagerIdentity, role models.TenantRole) (*models.Membership, error) {
	if !validIdentity(target.Issuer, target.Subject) || !models.IsTenantRole(role) {
		return nil, errs.ErrTenantManagerValidation
	}
	if target.Issuer == actor.Issuer && target.Subject == actor.Subject {
		return nil, errs.ErrTenantManagerSelfModification
	}
	membership, err := svc.repo.AssignMembership(ctx, &models.Membership{
		ID:              uuid.NewString(),
		TenantID:        tenantID,
		IdentityIssuer:  target.Issuer,
		IdentitySubject: target.Subject,
		Role:            role,
		Status:          models.MembershipActive,
		CreatedAt:       svc.now(),
	})
	if err != nil {
		return nil, err
	}
	svc.audit(actor, "membership.assign", logrus.Fields{
		"tenant_id": tenantID, "membership_id": membership.ID,
		"target_issuer": target.Issuer, "target_subject": target.Subject, "new_role": role,
	})
	return membership, nil
}

func (svc *TenantManagerService) UpdateMembership(ctx context.Context, actor TenantManagerActor, tenantID string, membershipID string, update models.MembershipUpdate) (*models.Membership, error) {
	if update.Role == nil && update.Status == nil {
		return nil, errs.ErrTenantManagerValidation
	}
	if update.Role != nil && !models.IsTenantRole(*update.Role) {
		return nil, errs.ErrTenantManagerValidation
	}
	if update.Status != nil && *update.Status != models.MembershipActive && *update.Status != models.MembershipSuspended {
		return nil, errs.ErrTenantManagerValidation
	}
	return svc.changeMembership(ctx, actor, tenantID, membershipID, update, "membership.update")
}

func (svc *TenantManagerService) RevokeMembership(ctx context.Context, actor TenantManagerActor, tenantID string, membershipID string) (*models.Membership, error) {
	revoked := models.MembershipRevoked
	return svc.changeMembership(ctx, actor, tenantID, membershipID, models.MembershipUpdate{Status: &revoked}, "membership.revoke")
}

func (svc *TenantManagerService) changeMembership(ctx context.Context, actor TenantManagerActor, tenantID string, membershipID string, update models.MembershipUpdate, action string) (*models.Membership, error) {
	current, err := svc.repo.GetTenantMembership(ctx, tenantID, membershipID)
	if err != nil {
		return nil, err
	}
	if current.IdentityIssuer == actor.Issuer && current.IdentitySubject == actor.Subject {
		return nil, errs.ErrTenantManagerSelfModification
	}
	updated, err := svc.repo.UpdateMembership(ctx, tenantID, membershipID, update)
	if err != nil {
		return nil, err
	}
	svc.audit(actor, action, logrus.Fields{
		"tenant_id": tenantID, "membership_id": membershipID,
		"target_issuer": current.IdentityIssuer, "target_subject": current.IdentitySubject,
		"old_role": current.Role, "new_role": updated.Role,
		"old_status": current.Status, "new_status": updated.Status,
	})
	return updated, nil
}

func (svc *TenantManagerService) ListInvitations(ctx context.Context, tenantID string) ([]models.Invitation, error) {
	return svc.repo.ListInvitations(ctx, tenantID)
}

func hashInvitationCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// CreateInvitation returns the stored invitation and its one-time code. Only
// the SHA-256 of the code is persisted.
func (svc *TenantManagerService) CreateInvitation(ctx context.Context, actor TenantManagerActor, tenantID string, role models.TenantRole, ttl time.Duration) (*models.Invitation, string, error) {
	if ttl == 0 {
		ttl = DefaultInvitationTTL
	}
	if !models.IsTenantRole(role) || ttl < time.Minute || ttl > MaxInvitationTTL {
		return nil, "", errs.ErrTenantManagerValidation
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", fmt.Errorf("generate invitation code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(secret)
	now := svc.now()
	invitation := &models.Invitation{
		ID:               uuid.NewString(),
		TenantID:         tenantID,
		Role:             role,
		CodeHash:         hashInvitationCode(code),
		Status:           models.InvitationPending,
		CreatedByIssuer:  actor.Issuer,
		CreatedBySubject: actor.Subject,
		ExpiresAt:        now.Add(ttl),
		CreatedAt:        now,
	}
	if err := svc.repo.CreateInvitation(ctx, invitation); err != nil {
		return nil, "", err
	}
	svc.audit(actor, "invitation.create", logrus.Fields{
		"tenant_id": tenantID, "invitation_id": invitation.ID, "new_role": role, "expires_at": invitation.ExpiresAt,
	})
	return invitation, code, nil
}

func (svc *TenantManagerService) RevokeInvitation(ctx context.Context, actor TenantManagerActor, tenantID string, invitationID string) (*models.Invitation, error) {
	invitation, err := svc.repo.RevokeInvitation(ctx, tenantID, invitationID)
	if err != nil {
		return nil, err
	}
	svc.audit(actor, "invitation.revoke", logrus.Fields{"tenant_id": tenantID, "invitation_id": invitationID})
	return invitation, nil
}

func (svc *TenantManagerService) AcceptInvitation(ctx context.Context, actor TenantManagerActor, code string) (*models.Membership, error) {
	if strings.TrimSpace(code) == "" {
		return nil, errs.ErrTenantManagerInvalidInvitation
	}
	membership, err := svc.repo.AcceptInvitation(ctx, hashInvitationCode(code), actor.Issuer, actor.Subject, uuid.NewString(), svc.now())
	if err != nil {
		return nil, err
	}
	svc.audit(actor, "invitation.accept", logrus.Fields{
		"tenant_id": membership.TenantID, "membership_id": membership.ID, "new_role": membership.Role,
	})
	return membership, nil
}
