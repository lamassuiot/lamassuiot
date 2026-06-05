package eventpub

import (
	"context"
	"fmt"

	authzmodels "github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/service"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	coremodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	beventpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
)

type principalEventPublisher struct {
	next service.PrincipalService
	pub  beventpub.ICloudEventPublisher
}

// NewPrincipalEventPublisher returns a middleware that publishes cloud events for
// mutating principal operations when they succeed.
func NewPrincipalEventPublisher(pub beventpub.ICloudEventPublisher) func(service.PrincipalService) service.PrincipalService {
	return func(next service.PrincipalService) service.PrincipalService {
		return &principalEventPublisher{
			next: next,
			pub:  beventpub.NewEventPublisherWithSourceMiddleware(pub, authzmodels.AuthzSource),
		}
	}
}

func setEvent(ctx context.Context, eventType coremodels.EventType, subject string) context.Context {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, eventType)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, subject)
	return ctx
}

func (p *principalEventPublisher) CreatePrincipal(ctx context.Context, principal *authzmodels.Principal) (err error) {
	ctx = setEvent(ctx, authzmodels.EventCreatePrincipalKey, fmt.Sprintf("principal/%s", principal.ID))
	defer func() {
		if err == nil {
			p.pub.PublishCloudEvent(ctx, principal)
		}
	}()
	return p.next.CreatePrincipal(ctx, principal)
}

func (p *principalEventPublisher) UpdatePrincipal(ctx context.Context, principal *authzmodels.Principal) (err error) {
	ctx = setEvent(ctx, authzmodels.EventUpdatePrincipalKey, fmt.Sprintf("principal/%s", principal.ID))
	defer func() {
		if err == nil {
			p.pub.PublishCloudEvent(ctx, principal)
		}
	}()
	return p.next.UpdatePrincipal(ctx, principal)
}

func (p *principalEventPublisher) DeletePrincipal(ctx context.Context, id string) (err error) {
	ctx = setEvent(ctx, authzmodels.EventDeletePrincipalKey, fmt.Sprintf("principal/%s", id))
	defer func() {
		if err == nil {
			p.pub.PublishCloudEvent(ctx, map[string]string{"id": id})
		}
	}()
	return p.next.DeletePrincipal(ctx, id)
}

func (p *principalEventPublisher) GrantPolicy(ctx context.Context, principalID, policyID, grantedBy string) (err error) {
	ctx = setEvent(ctx, authzmodels.EventGrantPolicyKey, fmt.Sprintf("principal/%s/policy/%s", principalID, policyID))
	defer func() {
		if err == nil {
			p.pub.PublishCloudEvent(ctx, map[string]string{"principal_id": principalID, "policy_id": policyID, "granted_by": grantedBy})
		}
	}()
	return p.next.GrantPolicy(ctx, principalID, policyID, grantedBy)
}

func (p *principalEventPublisher) RevokePolicy(ctx context.Context, principalID, policyID string) (err error) {
	ctx = setEvent(ctx, authzmodels.EventRevokePolicyKey, fmt.Sprintf("principal/%s/policy/%s", principalID, policyID))
	defer func() {
		if err == nil {
			p.pub.PublishCloudEvent(ctx, map[string]string{"principal_id": principalID, "policy_id": policyID})
		}
	}()
	return p.next.RevokePolicy(ctx, principalID, policyID)
}

// Pass-through methods (read-only, no events).

func (p *principalEventPublisher) GetPrincipal(ctx context.Context, id string) (*authzmodels.Principal, error) {
	return p.next.GetPrincipal(ctx, id)
}

func (p *principalEventPublisher) GetPrincipalWithPolicies(ctx context.Context, id string) (*authzmodels.Principal, error) {
	return p.next.GetPrincipalWithPolicies(ctx, id)
}

func (p *principalEventPublisher) ListPrincipals(ctx context.Context, queryParams *resources.QueryParameters) ([]*authzmodels.Principal, error) {
	return p.next.ListPrincipals(ctx, queryParams)
}

func (p *principalEventPublisher) GetPrincipalPolicies(ctx context.Context, principalID string) ([]authzmodels.PrincipalPolicy, error) {
	return p.next.GetPrincipalPolicies(ctx, principalID)
}

func (p *principalEventPublisher) CountPolicyPrincipals(ctx context.Context, policyID string) (int64, error) {
	return p.next.CountPolicyPrincipals(ctx, policyID)
}
