package catokms

import (
	"context"
	"errors"
	"testing"
	"time"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type promotionProvisionerStub struct {
	candidate PromotionCandidate
	rollback  int
}

func (stub *promotionProvisionerStub) Provision(_ context.Context, tenantID string, _ string, _ string, _ string) (PromotionCandidate, error) {
	stub.candidate.TenantID = tenantID
	return stub.candidate, nil
}

func (stub *promotionProvisionerStub) Rollback(_ context.Context, _ PromotionCandidate) error {
	stub.rollback++
	return nil
}

type promotionVerifierStub struct{ err error }

func (stub promotionVerifierStub) Verify(_ context.Context, _ PromotionCandidate) error {
	return stub.err
}

type promotionSelectorStub struct{ err error }

func (stub promotionSelectorStub) Initialize(_ context.Context, _ PromotionCandidate) error {
	return nil
}

func (stub promotionSelectorStub) Switch(_ context.Context, _ string, _ string, _ PromotionCandidate) error {
	return stub.err
}

func promotionContext() context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-a",
		TenantID:       "tenant-a",
		ActorID:        "actor-a",
		ActorType:      "user",
		CorrelationID:  "correlation-a",
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

func promotionRequest() PromotionRequest {
	now := time.Date(2026, time.September, 22, 12, 0, 0, 0, time.UTC)
	return PromotionRequest{
		CurrentCAID:     "shared-ca",
		CurrentEngineID: "shared-engine",
		CurrentKeyID:    "shared-key",
		OperationID:     "promotion-1",
		TargetEngineID:  "dedicated-engine",
		TargetIsolation: models.IsolationDedicatedCrypto,
		Approval: PromotionApproval{
			TenantID:   "tenant-a",
			ApprovalID: "approval-1",
			ApprovedBy: "security-owner",
			ApprovedAt: now.Add(-time.Hour),
			ExpiresAt:  now.Add(time.Hour),
		},
		Now: now,
	}
}

func promotionCandidate() PromotionCandidate {
	return PromotionCandidate{EngineID: "dedicated-engine", KeyID: "dedicated-key", CAID: "dedicated-ca", PublicKey: "public-key"}
}

func TestPromoteToDedicatedCrypto_SucceedsAfterVerification(t *testing.T) {
	provisioner := &promotionProvisionerStub{candidate: promotionCandidate()}
	result, err := PromoteToDedicatedCrypto(promotionContext(), silentLogger(), promotionRequest(), provisioner, promotionVerifierStub{}, promotionSelectorStub{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if result.State != PromotionActive || provisioner.rollback != 0 {
		t.Fatalf("result=%+v rollback=%d, want active without rollback", result, provisioner.rollback)
	}
}

func TestPromoteToDedicatedCrypto_RollsBackWhenVerificationFails(t *testing.T) {
	provisioner := &promotionProvisionerStub{candidate: promotionCandidate()}
	result, err := PromoteToDedicatedCrypto(promotionContext(), silentLogger(), promotionRequest(), provisioner, promotionVerifierStub{err: errors.New("bad signature")}, promotionSelectorStub{})
	if err == nil || result.State != PromotionRollingBack || provisioner.rollback != 1 {
		t.Fatalf("result=%+v err=%v rollback=%d, want verification failure with rollback", result, err, provisioner.rollback)
	}
}

func TestPromoteToDedicatedCrypto_RollsBackWhenSelectorSwitchFails(t *testing.T) {
	provisioner := &promotionProvisionerStub{candidate: promotionCandidate()}
	result, err := PromoteToDedicatedCrypto(promotionContext(), silentLogger(), promotionRequest(), provisioner, promotionVerifierStub{}, promotionSelectorStub{err: errors.New("selector unavailable")})
	if err == nil || result.State != PromotionRollingBack || provisioner.rollback != 1 {
		t.Fatalf("result=%+v err=%v rollback=%d, want selector failure with rollback", result, err, provisioner.rollback)
	}
}

func TestPromoteToDedicatedCrypto_RejectsMissingOrForeignScope(t *testing.T) {
	provisioner := &promotionProvisionerStub{candidate: promotionCandidate()}
	request := promotionRequest()
	request.Approval.TenantID = "tenant-b"
	_, err := PromoteToDedicatedCrypto(promotionContext(), silentLogger(), request, provisioner, promotionVerifierStub{}, promotionSelectorStub{})
	if !errors.Is(err, core.ErrTenantResourceAccessDenied) {
		t.Fatalf("expected tenant access error, got %v", err)
	}

	_, err = PromoteToDedicatedCrypto(context.Background(), silentLogger(), promotionRequest(), provisioner, promotionVerifierStub{}, promotionSelectorStub{})
	if !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected tenant context error, got %v", err)
	}
}

func TestPromoteToDedicatedCrypto_FailsClosedWithoutCapabilities(t *testing.T) {
	_, err := PromoteToDedicatedCrypto(promotionContext(), silentLogger(), promotionRequest(), nil, promotionVerifierStub{}, promotionSelectorStub{})
	if !errors.Is(err, ErrPromotionUnavailable) {
		t.Fatalf("expected unavailable promotion error, got %v", err)
	}
}
