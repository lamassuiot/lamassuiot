package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"gorm.io/gorm"
)

// GormPolicyStore persists Policy objects in a Postgres table via the postgresDBQuerier.
// AutoMigrate is called at construction time to create the "policies" table if missing.
type GormPolicyStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.PolicyRecord]
}

// NewGormPolicyStore creates the store. Schema is managed by RunMigrations.
func NewGormPolicyStore(db *gorm.DB) (*GormPolicyStore, error) {
	q := newPostgresDBQuerier[models.PolicyRecord](db, "policies", "id")
	return &GormPolicyStore{db: db, querier: &q}, nil
}

func (s *GormPolicyStore) Create(ctx context.Context, policy *models.Policy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	exists, err := s.Exists(ctx, policy.ID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("policy with ID %s already exists", policy.ID)
	}
	rec, err := models.PolicyRecordFromPolicy(policy)
	if err != nil {
		return err
	}
	_, err = s.querier.Insert(ctx, rec, rec.ID)
	return err
}

func (s *GormPolicyStore) Exists(ctx context.Context, id string) (bool, error) {
	found, _, err := s.querier.SelectExists(ctx, id, nil)
	return found, err
}

func (s *GormPolicyStore) Get(ctx context.Context, id string) (*models.Policy, error) {
	found, rec, err := s.querier.SelectExists(ctx, id, nil)
	if err != nil {
		return nil, fmt.Errorf("get policy %s: %w", id, err)
	}
	if !found {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	return rec.ToPolicy()
}

func (s *GormPolicyStore) Update(ctx context.Context, policy *models.Policy) error {
	exists, err := s.Exists(ctx, policy.ID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("policy not found: %s", policy.ID)
	}
	rec, err := models.PolicyRecordFromPolicy(policy)
	if err != nil {
		return err
	}
	_, err = s.querier.Update(ctx, rec, rec.ID)
	return err
}

func (s *GormPolicyStore) Delete(ctx context.Context, id string) error {
	exists, err := s.Exists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("policy not found: %s", id)
	}
	return s.querier.Delete(ctx, id)
}

func (s *GormPolicyStore) List(ctx context.Context, queryParams *resources.QueryParameters) ([]*models.Policy, string, error) {
	var policies []*models.Policy
	nextBookmark, err := s.querier.SelectAll(ctx, queryParams, []gormExtraOps{}, false, func(rec models.PolicyRecord) {
		p, convErr := rec.ToPolicy()
		if convErr == nil {
			policies = append(policies, p)
		}
	})
	return policies, nextBookmark, err
}

func (s *GormPolicyStore) Search(ctx context.Context, query string) ([]*models.Policy, error) {
	if query == "" {
		policies, _, err := s.List(ctx, nil)
		return policies, err
	}

	var records []models.PolicyRecord
	lower := strings.ToLower(query)
	if err := s.db.WithContext(ctx).
		Table("policies").
		Where("LOWER(id) LIKE ? OR LOWER(name) ILIKE ? OR LOWER(description) ILIKE ?",
			"%"+lower+"%", "%"+lower+"%", "%"+lower+"%").
		Find(&records).Error; err != nil {
		return nil, fmt.Errorf("search policies: %w", err)
	}

	out := make([]*models.Policy, 0, len(records))
	for i := range records {
		p, err := records[i].ToPolicy()
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}
