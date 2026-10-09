package eventpub

import (
	"context"
	"fmt"

	authzmodels "github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	beventpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
)

type policyEventPublisher struct {
	next service.PolicyService
	pub  beventpub.ICloudEventPublisher
}

// NewPolicyEventPublisher returns a middleware that publishes cloud events for
// mutating policy operations when they succeed.
func NewPolicyEventPublisher(pub beventpub.ICloudEventPublisher) func(service.PolicyService) service.PolicyService {
	return func(next service.PolicyService) service.PolicyService {
		return &policyEventPublisher{
			next: next,
			pub:  beventpub.NewEventPublisherWithSourceMiddleware(pub, authzmodels.AuthzSource),
		}
	}
}

func (p *policyEventPublisher) CreatePolicy(ctx context.Context, policy *authzmodels.Policy) (err error) {
	ctx = setEvent(ctx, authzmodels.EventCreatePolicyKey, fmt.Sprintf("policy/%s", policy.ID))
	defer func() {
		if err == nil {
			p.pub.PublishCloudEvent(ctx, policy)
		}
	}()
	return p.next.CreatePolicy(ctx, policy)
}

func (p *policyEventPublisher) UpdatePolicy(ctx context.Context, policy *authzmodels.Policy) (err error) {
	ctx = setEvent(ctx, authzmodels.EventUpdatePolicyKey, fmt.Sprintf("policy/%s", policy.ID))
	defer func() {
		if err == nil {
			p.pub.PublishCloudEvent(ctx, policy)
		}
	}()
	return p.next.UpdatePolicy(ctx, policy)
}

func (p *policyEventPublisher) DeletePolicy(ctx context.Context, policyID string) (err error) {
	ctx = setEvent(ctx, authzmodels.EventDeletePolicyKey, fmt.Sprintf("policy/%s", policyID))
	defer func() {
		if err == nil {
			p.pub.PublishCloudEvent(ctx, map[string]string{"id": policyID})
		}
	}()
	return p.next.DeletePolicy(ctx, policyID)
}

// Pass-through methods (read-only, no events).

func (p *policyEventPublisher) GetPolicy(ctx context.Context, policyID string) (*authzmodels.Policy, error) {
	return p.next.GetPolicy(ctx, policyID)
}

func (p *policyEventPublisher) ListPolicies(ctx context.Context, queryParams *resources.QueryParameters) ([]*authzmodels.Policy, string, error) {
	return p.next.ListPolicies(ctx, queryParams)
}

func (p *policyEventPublisher) SearchPolicies(ctx context.Context, query string) ([]*authzmodels.Policy, error) {
	return p.next.SearchPolicies(ctx, query)
}

