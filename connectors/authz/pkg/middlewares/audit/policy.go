package audit

import (
	"context"

	authzmodels "github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	beventpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	baudit "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/audit"
)

type policyAuditPublisher struct {
	next     service.PolicyService
	auditPub baudit.AuditPublisher
}

// NewPolicyAuditPublisher wraps a PolicyService and publishes audit records for
// every mutating call (success or failure).
func NewPolicyAuditPublisher(audit baudit.AuditPublisher) func(service.PolicyService) service.PolicyService {
	return func(next service.PolicyService) service.PolicyService {
		return &policyAuditPublisher{
			next: next,
			auditPub: baudit.AuditPublisher{
				ICloudEventPublisher: beventpub.NewEventPublisherWithSourceMiddleware(audit, authzmodels.AuthzSource),
			},
		}
	}
}

func (p *policyAuditPublisher) CreatePolicy(ctx context.Context, policy *authzmodels.Policy) (err error) {
	defer func() {
		p.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, authzmodels.EventCreatePolicyKey, policy, err, policy)
	}()
	return p.next.CreatePolicy(ctx, policy)
}

func (p *policyAuditPublisher) UpdatePolicy(ctx context.Context, policy *authzmodels.Policy) (err error) {
	defer func() {
		p.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, authzmodels.EventUpdatePolicyKey, policy, err, policy)
	}()
	return p.next.UpdatePolicy(ctx, policy)
}

func (p *policyAuditPublisher) DeletePolicy(ctx context.Context, policyID string) (err error) {
	defer func() {
		p.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, authzmodels.EventDeletePolicyKey, map[string]string{"id": policyID}, err, nil)
	}()
	return p.next.DeletePolicy(ctx, policyID)
}

// Pass-through methods.

func (p *policyAuditPublisher) GetPolicy(ctx context.Context, policyID string) (*authzmodels.Policy, error) {
	return p.next.GetPolicy(ctx, policyID)
}

func (p *policyAuditPublisher) ListPolicies(ctx context.Context, queryParams *resources.QueryParameters) ([]*authzmodels.Policy, string, error) {
	return p.next.ListPolicies(ctx, queryParams)
}

func (p *policyAuditPublisher) SearchPolicies(ctx context.Context, query string) ([]*authzmodels.Policy, error) {
	return p.next.SearchPolicies(ctx, query)
}
