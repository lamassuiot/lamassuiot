package audit

import (
	"context"

	authzmodels "github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/service"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	beventpub "github.com/lamassuiot/lamassuiot/pki/v3/pkg/middlewares/eventpub"
	baudit "github.com/lamassuiot/lamassuiot/pki/v3/pkg/middlewares/audit"
)

type principalAuditPublisher struct {
	next     service.PrincipalService
	auditPub baudit.AuditPublisher
}

// NewPrincipalAuditPublisher wraps a PrincipalService and publishes audit records for
// every mutating call (success or failure).
func NewPrincipalAuditPublisher(audit baudit.AuditPublisher) func(service.PrincipalService) service.PrincipalService {
	return func(next service.PrincipalService) service.PrincipalService {
		return &principalAuditPublisher{
			next: next,
			auditPub: baudit.AuditPublisher{
				ICloudEventPublisher: beventpub.NewEventPublisherWithSourceMiddleware(audit, authzmodels.AuthzSource),
			},
		}
	}
}

func (p *principalAuditPublisher) CreatePrincipal(ctx context.Context, principal *authzmodels.Principal) (err error) {
	defer func() {
		p.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, authzmodels.EventCreatePrincipalKey, principal, err, principal)
	}()
	return p.next.CreatePrincipal(ctx, principal)
}

func (p *principalAuditPublisher) UpdatePrincipal(ctx context.Context, principal *authzmodels.Principal) (err error) {
	defer func() {
		p.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, authzmodels.EventUpdatePrincipalKey, principal, err, principal)
	}()
	return p.next.UpdatePrincipal(ctx, principal)
}

func (p *principalAuditPublisher) DeletePrincipal(ctx context.Context, id string) (err error) {
	defer func() {
		p.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, authzmodels.EventDeletePrincipalKey, map[string]string{"id": id}, err, nil)
	}()
	return p.next.DeletePrincipal(ctx, id)
}

func (p *principalAuditPublisher) GrantPolicy(ctx context.Context, principalID, policyID, grantedBy string) (err error) {
	input := map[string]string{"principal_id": principalID, "policy_id": policyID, "granted_by": grantedBy}
	defer func() {
		p.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, authzmodels.EventGrantPolicyKey, input, err, nil)
	}()
	return p.next.GrantPolicy(ctx, principalID, policyID, grantedBy)
}

func (p *principalAuditPublisher) RevokePolicy(ctx context.Context, principalID, policyID string) (err error) {
	input := map[string]string{"principal_id": principalID, "policy_id": policyID}
	defer func() {
		p.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, authzmodels.EventRevokePolicyKey, input, err, nil)
	}()
	return p.next.RevokePolicy(ctx, principalID, policyID)
}

// Pass-through methods.

func (p *principalAuditPublisher) GetPrincipal(ctx context.Context, id string) (*authzmodels.Principal, error) {
	return p.next.GetPrincipal(ctx, id)
}

func (p *principalAuditPublisher) GetPrincipalWithPolicies(ctx context.Context, id string) (*authzmodels.Principal, error) {
	return p.next.GetPrincipalWithPolicies(ctx, id)
}

func (p *principalAuditPublisher) ListPrincipals(ctx context.Context, queryParams *resources.QueryParameters) ([]*authzmodels.Principal, string, error) {
	return p.next.ListPrincipals(ctx, queryParams)
}

func (p *principalAuditPublisher) GetPrincipalPolicies(ctx context.Context, principalID string, queryParams *resources.QueryParameters) ([]authzmodels.PrincipalPolicy, string, error) {
	return p.next.GetPrincipalPolicies(ctx, principalID, queryParams)
}

func (p *principalAuditPublisher) CountPolicyPrincipals(ctx context.Context, policyID string) (int64, error) {
	return p.next.CountPolicyPrincipals(ctx, policyID)
}
