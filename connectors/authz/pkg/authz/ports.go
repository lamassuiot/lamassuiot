package authz

import (
	"context"

	"github.com/lamassuiot/authz/pkg/models"
)

// PrincipalStore is the persistence port for principal CRUD and loading.
type PrincipalStore interface {
	Create(ctx context.Context, p *models.Principal) error
	Get(ctx context.Context, id string) (*models.Principal, error)
	GetWithPolicies(ctx context.Context, id string) (*models.Principal, error)
	List(ctx context.Context, activeOnly bool) ([]*models.Principal, error)
	Update(ctx context.Context, p *models.Principal) error
	Delete(ctx context.Context, id string) error
	SetActive(ctx context.Context, id string, active bool) error

	// ListByType returns all active principals of a given auth type.
	// Used by MatchService to feed the matcher without loading all principals.
	ListByType(ctx context.Context, authType string) ([]models.Principal, error)
}

// GrantStore is the persistence port for the principal_policies join table.
type GrantStore interface {
	Grant(ctx context.Context, principalID, policyID, grantedBy string) error
	Revoke(ctx context.Context, principalID, policyID string) error
	GrantBatch(ctx context.Context, principalID string, policyIDs []string, grantedBy string) error
	RevokeBatch(ctx context.Context, principalID string, policyIDs []string) error
	Has(ctx context.Context, principalID, policyID string) (bool, error)
	ListForPrincipal(ctx context.Context, principalID string) ([]string, error)
	ListForPolicy(ctx context.Context, policyID string) ([]*models.Principal, error)
	CountForPrincipal(ctx context.Context, principalID string) (int64, error)
	CountForPolicy(ctx context.Context, policyID string) (int64, error)
}

// PrincipalMatcher is the pure matching port. Each implementation handles one auth type;
// the auth type is baked into the implementation rather than passed as a string parameter.
// Implementations must hold no *gorm.DB — the caller pre-loads principals via ListByType.
type PrincipalMatcher interface {
	Match(principals []models.Principal, authMaterial interface{}) ([]string, error)
}
