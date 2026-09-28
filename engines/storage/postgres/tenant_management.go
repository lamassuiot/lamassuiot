package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const postgresUniqueViolation = "23505"

// TenantManagementStore implements storage.TenantManagementRepo on the
// control plane database. Membership and invitation mutations lock the tenant
// row first, so concurrent changes to the same tenant are serialized.
type TenantManagementStore struct {
	db *gorm.DB
}

func NewTenantManagementRepository(db *gorm.DB) *TenantManagementStore {
	return &TenantManagementStore{db: db}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == postgresUniqueViolation
}

func notFoundOr(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return errs.ErrTenantManagerNotFound
	}
	return err
}

func (store *TenantManagementStore) CreateOrganization(ctx context.Context, organization *models.Organization) error {
	if err := store.db.WithContext(ctx).Create(organization).Error; err != nil {
		if isUniqueViolation(err) {
			return errs.ErrTenantManagerConflict
		}
		return fmt.Errorf("create organization: %w", err)
	}
	return nil
}

func (store *TenantManagementStore) ListOrganizations(ctx context.Context) ([]models.Organization, error) {
	organizations := []models.Organization{}
	if err := store.db.WithContext(ctx).Order("name, id").Find(&organizations).Error; err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	return organizations, nil
}

func ensureIdentity(tx *gorm.DB, issuer string, subject string) error {
	identity := models.Identity{Issuer: issuer, Subject: subject}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&identity).Error; err != nil {
		return fmt.Errorf("register identity: %w", err)
	}
	return nil
}

func (store *TenantManagementStore) CreateTenantWithAdmin(ctx context.Context, tenant *models.Tenant, admin *models.Membership) error {
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var organization models.Organization
		if err := tx.Where("id = ?", tenant.OrganizationID).First(&organization).Error; err != nil {
			return notFoundOr(err)
		}
		if err := tx.Create(tenant).Error; err != nil {
			if isUniqueViolation(err) {
				return errs.ErrTenantManagerConflict
			}
			return fmt.Errorf("create tenant: %w", err)
		}
		if err := ensureIdentity(tx, admin.IdentityIssuer, admin.IdentitySubject); err != nil {
			return err
		}
		if err := tx.Create(admin).Error; err != nil {
			return fmt.Errorf("create initial tenant_admin membership: %w", err)
		}
		return nil
	})
}

func (store *TenantManagementStore) ListTenants(ctx context.Context, organizationID string) ([]models.Tenant, error) {
	tenants := []models.Tenant{}
	query := store.db.WithContext(ctx).Order("organization_id, name, id")
	if organizationID != "" {
		query = query.Where("organization_id = ?", organizationID)
	}
	if err := query.Find(&tenants).Error; err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return tenants, nil
}

func lockTenant(tx *gorm.DB, tenantID string) (*models.Tenant, error) {
	var tenant models.Tenant
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return nil, notFoundOr(err)
	}
	return &tenant, nil
}

func (store *TenantManagementStore) UpdateTenantStatus(ctx context.Context, tenantID string, status models.TenantStatus, at time.Time) (*models.Tenant, error) {
	var updated *models.Tenant
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tenant, err := lockTenant(tx, tenantID)
		if err != nil {
			return err
		}
		if !models.CanTransitionTenantStatus(tenant.Status, status) {
			return errs.ErrTenantManagerInvalidTransition
		}
		changes := map[string]any{"status": status}
		switch status {
		case models.TenantDeleted:
			changes["deleted_at"] = at
		case models.TenantRestoring:
			changes["deleted_at"] = nil
		}
		if err := tx.Model(&models.Tenant{}).Where("id = ?", tenantID).Updates(changes).Error; err != nil {
			return fmt.Errorf("update tenant status: %w", err)
		}
		updated = &models.Tenant{}
		return tx.Where("id = ?", tenantID).First(updated).Error
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (store *TenantManagementStore) ListIdentityMemberships(ctx context.Context, issuer string, subject string) ([]models.MembershipSummary, error) {
	summaries := []models.MembershipSummary{}
	err := store.db.WithContext(ctx).
		Table("memberships AS m").
		Select(`m.id AS membership_id, m.organization_id, o.name AS organization_name,
			m.tenant_id, t.name AS tenant_name, t.status AS tenant_status, m.role, m.status`).
		Joins("JOIN tenants t ON t.id = m.tenant_id").
		Joins("JOIN organizations o ON o.id = m.organization_id").
		Where("m.identity_issuer = ? AND m.identity_subject = ? AND m.status = ? AND t.deleted_at IS NULL",
			issuer, subject, models.MembershipActive).
		Order("o.name, t.name, m.id").
		Scan(&summaries).Error
	if err != nil {
		return nil, fmt.Errorf("list identity memberships: %w", err)
	}
	return summaries, nil
}

func (store *TenantManagementStore) ListTenantMemberships(ctx context.Context, tenantID string) ([]models.Membership, error) {
	memberships := []models.Membership{}
	err := store.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at, id").
		Find(&memberships).Error
	if err != nil {
		return nil, fmt.Errorf("list tenant memberships: %w", err)
	}
	return memberships, nil
}

func (store *TenantManagementStore) GetTenantMembership(ctx context.Context, tenantID string, membershipID string) (*models.Membership, error) {
	var membership models.Membership
	if err := store.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, membershipID).First(&membership).Error; err != nil {
		return nil, notFoundOr(err)
	}
	return &membership, nil
}

// grantMembership creates or reactivates the identity's membership in the
// locked tenant. The caller must hold the tenant lock.
func grantMembership(tx *gorm.DB, tenant *models.Tenant, issuer string, subject string, role models.TenantRole, newMembershipID string) (*models.Membership, error) {
	if err := ensureIdentity(tx, issuer, subject); err != nil {
		return nil, err
	}
	var existing models.Membership
	err := tx.Where("tenant_id = ? AND identity_issuer = ? AND identity_subject = ?", tenant.ID, issuer, subject).First(&existing).Error
	switch {
	case err == nil && existing.Status != models.MembershipRevoked:
		return nil, errs.ErrTenantManagerConflict
	case err == nil:
		if err := tx.Model(&models.Membership{}).Where("id = ?", existing.ID).
			Updates(map[string]any{"role": role, "status": models.MembershipActive}).Error; err != nil {
			return nil, fmt.Errorf("reactivate membership: %w", err)
		}
		existing.Role = role
		existing.Status = models.MembershipActive
		return &existing, nil
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return nil, fmt.Errorf("find membership: %w", err)
	}

	membership := &models.Membership{
		ID:              newMembershipID,
		OrganizationID:  tenant.OrganizationID,
		TenantID:        tenant.ID,
		IdentityIssuer:  issuer,
		IdentitySubject: subject,
		Role:            role,
		Status:          models.MembershipActive,
	}
	if err := tx.Create(membership).Error; err != nil {
		if isUniqueViolation(err) {
			return nil, errs.ErrTenantManagerConflict
		}
		return nil, fmt.Errorf("create membership: %w", err)
	}
	return membership, nil
}

func (store *TenantManagementStore) AssignMembership(ctx context.Context, membership *models.Membership) (*models.Membership, error) {
	var granted *models.Membership
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tenant, err := lockTenant(tx, membership.TenantID)
		if err != nil {
			return err
		}
		granted, err = grantMembership(tx, tenant, membership.IdentityIssuer, membership.IdentitySubject, membership.Role, membership.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return granted, nil
}

func (store *TenantManagementStore) UpdateMembership(ctx context.Context, tenantID string, membershipID string, update models.MembershipUpdate) (*models.Membership, error) {
	var updated models.Membership
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockTenant(tx, tenantID); err != nil {
			return err
		}
		if err := tx.Where("tenant_id = ? AND id = ?", tenantID, membershipID).First(&updated).Error; err != nil {
			return notFoundOr(err)
		}
		wasActiveAdmin := updated.Role == models.RoleTenantAdmin && updated.Status == models.MembershipActive
		if updated.Status == models.MembershipRevoked && update.Status != nil && *update.Status != models.MembershipRevoked {
			return errs.ErrTenantManagerConflict
		}
		if update.Role != nil {
			updated.Role = *update.Role
		}
		if update.Status != nil {
			updated.Status = *update.Status
		}
		stillActiveAdmin := updated.Role == models.RoleTenantAdmin && updated.Status == models.MembershipActive
		if wasActiveAdmin && !stillActiveAdmin {
			var otherAdmins int64
			if err := tx.Model(&models.Membership{}).
				Where("tenant_id = ? AND id <> ? AND role = ? AND status = ?", tenantID, membershipID, models.RoleTenantAdmin, models.MembershipActive).
				Count(&otherAdmins).Error; err != nil {
				return fmt.Errorf("count tenant admins: %w", err)
			}
			if otherAdmins == 0 {
				return errs.ErrTenantManagerLastTenantAdmin
			}
		}
		if err := tx.Model(&models.Membership{}).Where("id = ?", membershipID).
			Updates(map[string]any{"role": updated.Role, "status": updated.Status}).Error; err != nil {
			return fmt.Errorf("update membership: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

func (store *TenantManagementStore) CreateInvitation(ctx context.Context, invitation *models.Invitation) error {
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tenant, err := lockTenant(tx, invitation.TenantID)
		if err != nil {
			return err
		}
		invitation.OrganizationID = tenant.OrganizationID
		if err := tx.Create(invitation).Error; err != nil {
			if isUniqueViolation(err) {
				return errs.ErrTenantManagerConflict
			}
			return fmt.Errorf("create invitation: %w", err)
		}
		return nil
	})
}

func (store *TenantManagementStore) ListInvitations(ctx context.Context, tenantID string) ([]models.Invitation, error) {
	invitations := []models.Invitation{}
	if err := store.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Order("created_at DESC, id").Find(&invitations).Error; err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	return invitations, nil
}

func (store *TenantManagementStore) RevokeInvitation(ctx context.Context, tenantID string, invitationID string) (*models.Invitation, error) {
	var invitation models.Invitation
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("tenant_id = ? AND id = ?", tenantID, invitationID).First(&invitation).Error; err != nil {
			return notFoundOr(err)
		}
		if invitation.Status != models.InvitationPending {
			return errs.ErrTenantManagerConflict
		}
		invitation.Status = models.InvitationRevoked
		return tx.Model(&models.Invitation{}).Where("id = ?", invitationID).Update("status", models.InvitationRevoked).Error
	})
	if err != nil {
		return nil, err
	}
	return &invitation, nil
}

func (store *TenantManagementStore) AcceptInvitation(ctx context.Context, codeHash string, issuer string, subject string, newMembershipID string, at time.Time) (*models.Membership, error) {
	var granted *models.Membership
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var invitation models.Invitation
		if err := tx.Where("code_hash = ?", codeHash).First(&invitation).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errs.ErrTenantManagerInvalidInvitation
			}
			return fmt.Errorf("find invitation: %w", err)
		}
		tenant, err := lockTenant(tx, invitation.TenantID)
		if err != nil {
			return err
		}
		// Re-read with a row lock: a concurrent accept or revoke may have
		// changed the invitation after the first read.
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", invitation.ID).First(&invitation).Error; err != nil {
			return fmt.Errorf("reload invitation: %w", err)
		}
		if invitation.Status != models.InvitationPending || !at.Before(invitation.ExpiresAt) ||
			tenant.Status != models.TenantActive || tenant.DeletedAt != nil {
			return errs.ErrTenantManagerInvalidInvitation
		}
		granted, err = grantMembership(tx, tenant, issuer, subject, invitation.Role, newMembershipID)
		if err != nil {
			return err
		}
		return tx.Model(&models.Invitation{}).Where("id = ?", invitation.ID).Updates(map[string]any{
			"status":              models.InvitationAccepted,
			"accepted_by_issuer":  issuer,
			"accepted_by_subject": subject,
			"accepted_at":         at,
		}).Error
	})
	if err != nil {
		return nil, err
	}
	return granted, nil
}

var _ storage.TenantManagementRepo = (*TenantManagementStore)(nil)
var _ storage.TenantManagementStorageProvider = (*PostgresStorageEngine)(nil)
