package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lamassuiot/authz/pkg/models"
	"gorm.io/gorm"
)

// GormPrincipalStore implements both PrincipalStore and GrantStore against a *gorm.DB.
// Both interfaces must be satisfied by the same instance to share transaction context.
type GormPrincipalStore struct {
	db *gorm.DB
}

// NewGormPrincipalStore creates the store and runs AutoMigrate for principal tables.
func NewGormPrincipalStore(db *gorm.DB) (*GormPrincipalStore, error) {
	s := &GormPrincipalStore{db: db}
	if err := db.AutoMigrate(&models.Principal{}, &models.PrincipalPolicy{}); err != nil {
		return nil, fmt.Errorf("migrate principal tables: %w", err)
	}
	return s, nil
}

// --- PrincipalStore ---

func (s *GormPrincipalStore) Create(_ context.Context, p *models.Principal) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	if p.Name == "" {
		return fmt.Errorf("principal name is required")
	}
	if err := s.db.Create(p).Error; err != nil {
		return fmt.Errorf("create principal: %w", err)
	}
	return nil
}

func (s *GormPrincipalStore) Get(_ context.Context, id string) (*models.Principal, error) {
	var p models.Principal
	if err := s.db.First(&p, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("principal not found: %s", id)
		}
		return nil, fmt.Errorf("get principal: %w", err)
	}
	return &p, nil
}

func (s *GormPrincipalStore) GetWithPolicies(_ context.Context, id string) (*models.Principal, error) {
	var p models.Principal
	if err := s.db.Preload("Policies").First(&p, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("principal not found: %s", id)
		}
		return nil, fmt.Errorf("get principal with policies: %w", err)
	}
	return &p, nil
}

func (s *GormPrincipalStore) List(_ context.Context, activeOnly bool) ([]*models.Principal, error) {
	var principals []*models.Principal
	q := s.db
	if activeOnly {
		q = q.Where("active = ?", true)
	}
	if err := q.Find(&principals).Error; err != nil {
		return nil, fmt.Errorf("list principals: %w", err)
	}
	return principals, nil
}

func (s *GormPrincipalStore) Update(_ context.Context, p *models.Principal) error {
	result := s.db.Model(&models.Principal{}).Where("id = ?", p.ID).Updates(p)
	if result.Error != nil {
		return fmt.Errorf("update principal: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("principal not found: %s", p.ID)
	}
	return nil
}

func (s *GormPrincipalStore) Delete(_ context.Context, id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("principal_id = ?", id).Delete(&models.PrincipalPolicy{}).Error; err != nil {
			return fmt.Errorf("delete principal policies: %w", err)
		}
		result := tx.Delete(&models.Principal{}, "id = ?", id)
		if result.Error != nil {
			return fmt.Errorf("delete principal: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("principal not found: %s", id)
		}
		return nil
	})
}

func (s *GormPrincipalStore) SetActive(_ context.Context, id string, active bool) error {
	result := s.db.Model(&models.Principal{}).Where("id = ?", id).Update("active", active)
	if result.Error != nil {
		return fmt.Errorf("set principal active: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("principal not found: %s", id)
	}
	return nil
}

func (s *GormPrincipalStore) ListByType(_ context.Context, authType string) ([]models.Principal, error) {
	var principals []models.Principal
	if err := s.db.Where("type = ? AND active = ?", authType, true).Find(&principals).Error; err != nil {
		return nil, fmt.Errorf("list principals by type: %w", err)
	}
	return principals, nil
}

// --- GrantStore ---

func (s *GormPrincipalStore) Grant(_ context.Context, principalID, policyID, grantedBy string) error {
	var existing models.PrincipalPolicy
	result := s.db.Where("principal_id = ? AND policy_id = ?", principalID, policyID).First(&existing)
	if result.Error == nil {
		return fmt.Errorf("policy %s already granted to principal %s", policyID, principalID)
	}
	if result.Error != gorm.ErrRecordNotFound {
		return fmt.Errorf("check existing grant: %w", result.Error)
	}
	if err := s.db.Create(&models.PrincipalPolicy{
		PrincipalID: principalID,
		PolicyID:    policyID,
		GrantedBy:   grantedBy,
	}).Error; err != nil {
		return fmt.Errorf("grant policy: %w", err)
	}
	return nil
}

func (s *GormPrincipalStore) Revoke(_ context.Context, principalID, policyID string) error {
	result := s.db.Where("principal_id = ? AND policy_id = ?", principalID, policyID).
		Delete(&models.PrincipalPolicy{})
	if result.Error != nil {
		return fmt.Errorf("revoke policy: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("grant not found: principal=%s policy=%s", principalID, policyID)
	}
	return nil
}

func (s *GormPrincipalStore) GrantBatch(_ context.Context, principalID string, policyIDs []string, grantedBy string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, policyID := range policyIDs {
			var existing models.PrincipalPolicy
			result := tx.Where("principal_id = ? AND policy_id = ?", principalID, policyID).First(&existing)
			if result.Error == nil {
				continue // idempotent skip
			}
			if result.Error != gorm.ErrRecordNotFound {
				return fmt.Errorf("check existing grant for %s: %w", policyID, result.Error)
			}
			if err := tx.Create(&models.PrincipalPolicy{
				PrincipalID: principalID,
				PolicyID:    policyID,
				GrantedBy:   grantedBy,
			}).Error; err != nil {
				return fmt.Errorf("grant policy %s: %w", policyID, err)
			}
		}
		return nil
	})
}

func (s *GormPrincipalStore) RevokeBatch(_ context.Context, principalID string, policyIDs []string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, policyID := range policyIDs {
			if err := tx.Where("principal_id = ? AND policy_id = ?", principalID, policyID).
				Delete(&models.PrincipalPolicy{}).Error; err != nil {
				return fmt.Errorf("revoke policy %s: %w", policyID, err)
			}
		}
		return nil
	})
}

func (s *GormPrincipalStore) Has(_ context.Context, principalID, policyID string) (bool, error) {
	var count int64
	if err := s.db.Model(&models.PrincipalPolicy{}).
		Where("principal_id = ? AND policy_id = ?", principalID, policyID).
		Count(&count).Error; err != nil {
		return false, fmt.Errorf("check policy grant: %w", err)
	}
	return count > 0, nil
}

func (s *GormPrincipalStore) ListForPrincipal(_ context.Context, principalID string) ([]string, error) {
	var rows []models.PrincipalPolicy
	if err := s.db.Where("principal_id = ?", principalID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list grants for principal: %w", err)
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.PolicyID
	}
	return ids, nil
}

func (s *GormPrincipalStore) ListForPolicy(_ context.Context, policyID string) ([]*models.Principal, error) {
	var rows []models.PrincipalPolicy
	if err := s.db.Where("policy_id = ?", policyID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list grants for policy: %w", err)
	}
	out := make([]*models.Principal, 0, len(rows))
	for _, r := range rows {
		var p models.Principal
		if err := s.db.First(&p, "id = ?", r.PrincipalID).Error; err != nil {
			continue // principal deleted; skip silently
		}
		out = append(out, &p)
	}
	return out, nil
}

func (s *GormPrincipalStore) CountForPrincipal(_ context.Context, principalID string) (int64, error) {
	var count int64
	if err := s.db.Model(&models.PrincipalPolicy{}).
		Where("principal_id = ?", principalID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count grants for principal: %w", err)
	}
	return count, nil
}

func (s *GormPrincipalStore) CountForPolicy(_ context.Context, policyID string) (int64, error) {
	var count int64
	if err := s.db.Model(&models.PrincipalPolicy{}).
		Where("policy_id = ?", policyID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count grants for policy: %w", err)
	}
	return count, nil
}
