package authz

import (
	"context"

	"github.com/lamassuiot/authz/pkg/models"
	"gocloud.dev/blob"
	"gorm.io/gorm"
)

// PrincipalManager is a backward-compatible facade over GormPrincipalStore and MatchService.
// All existing call sites in pkg/api/ and pkg/authz/service.go compile unchanged.
// New code should depend on the individual ports (PrincipalStore, GrantStore, PrincipalMatcher)
// rather than this aggregate.
type PrincipalManager struct {
	store        *GormPrincipalStore
	matchService *MatchService
}

// NewPrincipalManager creates a PrincipalManager. The bucket parameter is accepted for
// API compatibility but is unused — policy storage is handled by PolicyManager.
func NewPrincipalManager(db *gorm.DB, _ *blob.Bucket) (*PrincipalManager, error) {
	store, err := NewGormPrincipalStore(db)
	if err != nil {
		return nil, err
	}
	return &PrincipalManager{
		store:        store,
		matchService: DefaultMatchService(store),
	}, nil
}

// --- Principal CRUD ---

func (m *PrincipalManager) CreatePrincipal(p *models.Principal) error {
	return m.store.Create(context.Background(), p)
}

func (m *PrincipalManager) GetPrincipal(id string) (*models.Principal, error) {
	return m.store.Get(context.Background(), id)
}

func (m *PrincipalManager) GetPrincipalWithPolicies(id string) (*models.Principal, error) {
	return m.store.GetWithPolicies(context.Background(), id)
}

func (m *PrincipalManager) ListPrincipals(activeOnly bool) ([]*models.Principal, error) {
	return m.store.List(context.Background(), activeOnly)
}

func (m *PrincipalManager) UpdatePrincipal(p *models.Principal) error {
	return m.store.Update(context.Background(), p)
}

func (m *PrincipalManager) DeletePrincipal(id string) error {
	return m.store.Delete(context.Background(), id)
}

func (m *PrincipalManager) SetPrincipalActive(id string, active bool) error {
	return m.store.SetActive(context.Background(), id, active)
}

// --- Policy grants ---

func (m *PrincipalManager) GrantPolicy(principalID, policyID, grantedBy string) error {
	// Preserve original behavior: verify principal exists before granting.
	if _, err := m.store.Get(context.Background(), principalID); err != nil {
		return err
	}
	return m.store.Grant(context.Background(), principalID, policyID, grantedBy)
}

func (m *PrincipalManager) RevokePolicy(principalID, policyID string) error {
	return m.store.Revoke(context.Background(), principalID, policyID)
}

func (m *PrincipalManager) GrantPolicies(principalID string, policyIDs []string, grantedBy string) error {
	return m.store.GrantBatch(context.Background(), principalID, policyIDs, grantedBy)
}

func (m *PrincipalManager) RevokePolicies(principalID string, policyIDs []string) error {
	return m.store.RevokeBatch(context.Background(), principalID, policyIDs)
}

func (m *PrincipalManager) HasPolicy(principalID, policyID string) (bool, error) {
	return m.store.Has(context.Background(), principalID, policyID)
}

func (m *PrincipalManager) GetPrincipalPolicies(principalID string) ([]string, error) {
	return m.store.ListForPrincipal(context.Background(), principalID)
}

func (m *PrincipalManager) GetPolicyPrincipals(policyID string) ([]*models.Principal, error) {
	return m.store.ListForPolicy(context.Background(), policyID)
}

func (m *PrincipalManager) CountPrincipalPolicies(principalID string) (int64, error) {
	return m.store.CountForPrincipal(context.Background(), principalID)
}

func (m *PrincipalManager) CountPolicyPrincipals(policyID string) (int64, error) {
	return m.store.CountForPolicy(context.Background(), policyID)
}

// NewIdentityResolver creates an IdentityResolver wired to this manager's store and
// match service. Use this in assembler.go to avoid exposing internal fields.
func (m *PrincipalManager) NewIdentityResolver(policies *PolicyManager) *IdentityResolver {
	return NewIdentityResolver(m.matchService, m.store, policies)
}

// --- Auth matching ---

func (m *PrincipalManager) MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error) {
	return m.matchService.MatchPrincipals(ctx, authMaterial, authType)
}
