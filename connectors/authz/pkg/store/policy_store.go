package store

import (
	"context"

	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

// PolicyStore is the persistence interface for Policy objects.
// GormPolicyStore provides the Postgres implementation; InMemoryPolicyStore is used in tests.
type PolicyStore interface {
	Create(ctx context.Context, policy *models.Policy) error
	Exists(ctx context.Context, id string) (bool, error)
	Get(ctx context.Context, id string) (*models.Policy, error)
	Update(ctx context.Context, policy *models.Policy) error
	Delete(ctx context.Context, id string) error
	// List returns a page of policies. nextBookmark is empty when there are no more pages.
	List(ctx context.Context, queryParams *resources.QueryParameters) ([]*models.Policy, string, error)
	// Search returns all policies whose ID, Name, or Description contain query (case-insensitive).
	// An empty query returns all policies.
	Search(ctx context.Context, query string) ([]*models.Policy, error)
}
