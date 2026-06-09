package service

import (
	"context"

	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/store"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"gorm.io/gorm"
)

// PrincipalManager is a facade over GormPrincipalStore and MatchService.
type PrincipalManager struct {
	store        *store.GormPrincipalStore
	matchService *store.MatchService
}

// NewPrincipalManager creates a PrincipalManager backed by the given Postgres DB.
func NewPrincipalManager(db *gorm.DB) (*PrincipalManager, error) {
	s, err := store.NewGormPrincipalStore(db)
	if err != nil {
		return nil, err
	}
	return &PrincipalManager{
		store:        s,
		matchService: store.DefaultMatchService(s),
	}, nil
}

// --- Principal CRUD ---

func (m *PrincipalManager) CreatePrincipal(ctx context.Context, p *models.Principal) error {
	return m.store.Create(ctx, p)
}

func (m *PrincipalManager) GetPrincipal(ctx context.Context, id string) (*models.Principal, error) {
	return m.store.Get(ctx, id)
}

func (m *PrincipalManager) GetPrincipalWithPolicies(ctx context.Context, id string) (*models.Principal, error) {
	return m.store.GetWithPolicies(ctx, id)
}

func (m *PrincipalManager) ListPrincipals(ctx context.Context, queryParams *resources.QueryParameters) ([]*models.Principal, string, error) {
	return m.store.List(ctx, queryParams)
}

func (m *PrincipalManager) UpdatePrincipal(ctx context.Context, p *models.Principal) error {
	return m.store.Update(ctx, p)
}

func (m *PrincipalManager) DeletePrincipal(ctx context.Context, id string) error {
	return m.store.Delete(ctx, id)
}

func (m *PrincipalManager) SetPrincipalActive(ctx context.Context, id string, active bool) error {
	return m.store.SetActive(ctx, id, active)
}

// --- Policy grants ---

func (m *PrincipalManager) GrantPolicy(ctx context.Context, principalID, policyID, grantedBy string) error {
	if _, err := m.store.Get(ctx, principalID); err != nil {
		return err
	}
	return m.store.Grant(ctx, principalID, policyID, grantedBy)
}

func (m *PrincipalManager) RevokePolicy(ctx context.Context, principalID, policyID string) error {
	return m.store.Revoke(ctx, principalID, policyID)
}

func (m *PrincipalManager) GrantPolicies(ctx context.Context, principalID string, policyIDs []string, grantedBy string) error {
	return m.store.GrantBatch(ctx, principalID, policyIDs, grantedBy)
}

func (m *PrincipalManager) RevokePolicies(ctx context.Context, principalID string, policyIDs []string) error {
	return m.store.RevokeBatch(ctx, principalID, policyIDs)
}

func (m *PrincipalManager) HasPolicy(ctx context.Context, principalID, policyID string) (bool, error) {
	return m.store.Has(ctx, principalID, policyID)
}

func (m *PrincipalManager) GetPrincipalPolicies(ctx context.Context, principalID string, queryParams *resources.QueryParameters) ([]models.PrincipalPolicy, string, error) {
	return m.store.ListForPrincipal(ctx, principalID, queryParams)
}

func (m *PrincipalManager) GetPolicyPrincipals(ctx context.Context, policyID string) ([]*models.Principal, error) {
	return m.store.ListForPolicy(ctx, policyID)
}

func (m *PrincipalManager) CountPrincipalPolicies(ctx context.Context, principalID string) (int64, error) {
	return m.store.CountForPrincipal(ctx, principalID)
}

func (m *PrincipalManager) CountPolicyPrincipals(ctx context.Context, policyID string) (int64, error) {
	return m.store.CountForPolicy(ctx, policyID)
}

// NewIdentityResolver creates an IdentityResolver wired to this manager's store and
// match service.
func (m *PrincipalManager) NewIdentityResolver(policies *PolicyManager) *IdentityResolver {
	return NewIdentityResolver(m.matchService, m.store, policies)
}

// --- Auth matching ---

func (m *PrincipalManager) MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error) {
	return m.matchService.MatchPrincipals(ctx, authMaterial, authType)
}
