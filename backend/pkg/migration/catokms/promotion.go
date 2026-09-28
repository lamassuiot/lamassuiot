package catokms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	log "github.com/sirupsen/logrus"
)

var ErrPromotionUnavailable = errors.New("dedicated crypto promotion is unavailable")

type PromotionState string

const (
	PromotionProvisioning PromotionState = "PROVISIONING"
	PromotionVerifying    PromotionState = "VERIFYING"
	PromotionActive       PromotionState = "ACTIVE"
	PromotionRollingBack  PromotionState = "ROLLING_BACK"
	PromotionFailed       PromotionState = "FAILED"
)

type PromotionRequest struct {
	CurrentCAID     string
	CurrentEngineID string
	CurrentKeyID    string
	OperationID     string
	TargetEngineID  string
	TargetIsolation models.IsolationMode
	Approval        PromotionApproval
	Now             time.Time
}

// PromotionApproval records the human approval for moving one tenant's CA to
// dedicated crypto resources.
type PromotionApproval struct {
	TenantID   string
	ApprovalID string
	ApprovedBy string
	ApprovedAt time.Time
	ExpiresAt  time.Time
}

func (approval PromotionApproval) Validate(now time.Time) error {
	if strings.TrimSpace(approval.TenantID) == "" || approval.TenantID == "*" {
		return errors.New("promotion approval requires an explicit tenant")
	}
	if strings.TrimSpace(approval.ApprovalID) == "" || strings.TrimSpace(approval.ApprovedBy) == "" {
		return errors.New("promotion approval requires an approval ID and approver")
	}
	if approval.ApprovedAt.IsZero() || !approval.ApprovedAt.Before(approval.ExpiresAt) {
		return errors.New("promotion approval requires a valid approval window")
	}
	if now.Before(approval.ApprovedAt) || !now.Before(approval.ExpiresAt) {
		return errors.New("promotion approval is not currently valid")
	}
	return nil
}

type PromotionCandidate struct {
	TenantID  string
	EngineID  string
	KeyID     string
	CAID      string
	PublicKey string
}

type PromotionResult struct {
	State     PromotionState
	Candidate PromotionCandidate
}

type PromotionProvisioner interface {
	Provision(ctx context.Context, tenantID string, currentCAID string, operationID string, targetEngineID string) (PromotionCandidate, error)
	Rollback(ctx context.Context, candidate PromotionCandidate) error
}

type PromotionVerifier interface {
	Verify(ctx context.Context, candidate PromotionCandidate) error
}

type PromotionSelector interface {
	Initialize(ctx context.Context, selector PromotionCandidate) error
	// Switch must be atomic: when it returns an error, the active selector is unchanged.
	Switch(ctx context.Context, tenantID string, currentCAID string, candidate PromotionCandidate) error
}

type StoragePromotionSelector struct {
	Repo storage.DedicatedCryptoSelectorRepo
}

func (selector StoragePromotionSelector) Initialize(ctx context.Context, candidate PromotionCandidate) error {
	if selector.Repo == nil {
		return ErrPromotionUnavailable
	}
	return selector.Repo.Initialize(ctx, models.DedicatedCryptoSelector{
		TenantID: candidate.TenantID,
		CAID:     candidate.CAID,
		EngineID: candidate.EngineID,
		KeyID:    candidate.KeyID,
	})
}

func (selector StoragePromotionSelector) Switch(ctx context.Context, tenantID string, currentCAID string, candidate PromotionCandidate) error {
	if selector.Repo == nil {
		return ErrPromotionUnavailable
	}
	return selector.Repo.Switch(ctx, currentCAID, models.DedicatedCryptoSelector{
		TenantID: tenantID,
		CAID:     candidate.CAID,
		EngineID: candidate.EngineID,
		KeyID:    candidate.KeyID,
	})
}

func PromoteToDedicatedCrypto(ctx context.Context, logger *log.Entry, request PromotionRequest, provisioner PromotionProvisioner, verifier PromotionVerifier, selector PromotionSelector) (PromotionResult, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return PromotionResult{State: PromotionFailed}, err
	}
	if provisioner == nil || verifier == nil || selector == nil {
		return PromotionResult{State: PromotionFailed}, ErrPromotionUnavailable
	}
	if request.CurrentCAID == "" || request.OperationID == "" {
		return PromotionResult{State: PromotionFailed}, errors.New("promotion requires current CA and operation identifiers")
	}
	if request.CurrentEngineID == "" || request.CurrentKeyID == "" {
		return PromotionResult{State: PromotionFailed}, errors.New("promotion requires the current CA engine and key")
	}
	if request.TargetEngineID == "" {
		return PromotionResult{State: PromotionFailed}, errors.New("promotion requires a dedicated target engine")
	}
	if request.TargetIsolation != models.IsolationDedicatedCrypto {
		return PromotionResult{State: PromotionFailed}, fmt.Errorf("promotion target must be %s", models.IsolationDedicatedCrypto)
	}
	if err := request.Approval.Validate(request.Now); err != nil {
		return PromotionResult{State: PromotionFailed}, fmt.Errorf("promotion approval rejected: %w", err)
	}
	if request.Approval.TenantID != tenantContext.TenantID {
		return PromotionResult{State: PromotionFailed}, core.ErrTenantResourceAccessDenied
	}

	result := PromotionResult{State: PromotionProvisioning}
	if err := selector.Initialize(ctx, PromotionCandidate{TenantID: tenantContext.TenantID, CAID: request.CurrentCAID, EngineID: request.CurrentEngineID, KeyID: request.CurrentKeyID}); err != nil && !errors.Is(err, storage.ErrDedicatedCryptoSelectorAlreadyInitialized) {
		return PromotionResult{State: PromotionFailed}, fmt.Errorf("initialize active crypto selector: %w", err)
	}
	candidate, err := provisioner.Provision(ctx, tenantContext.TenantID, request.CurrentCAID, request.OperationID, request.TargetEngineID)
	if err != nil {
		return PromotionResult{State: PromotionFailed}, fmt.Errorf("provision dedicated crypto resources: %w", err)
	}
	if candidate.TenantID != tenantContext.TenantID || candidate.EngineID == "" || candidate.KeyID == "" || candidate.CAID == "" || candidate.PublicKey == "" {
		return rollbackPromotion(ctx, logger, provisioner, candidate, errors.New("provisioned candidate is incomplete or belongs to another tenant"))
	}

	result.Candidate = candidate
	result.State = PromotionVerifying
	if err := verifier.Verify(ctx, candidate); err != nil {
		return rollbackPromotion(ctx, logger, provisioner, candidate, fmt.Errorf("verify dedicated crypto resources: %w", err))
	}
	if err := selector.Switch(ctx, tenantContext.TenantID, request.CurrentCAID, candidate); err != nil {
		return rollbackPromotion(ctx, logger, provisioner, candidate, fmt.Errorf("switch active CA selector: %w", err))
	}

	result.State = PromotionActive
	return result, nil
}

func rollbackPromotion(ctx context.Context, logger *log.Entry, provisioner PromotionProvisioner, candidate PromotionCandidate, cause error) (PromotionResult, error) {
	if err := provisioner.Rollback(ctx, candidate); err != nil {
		logger.Errorf("promotion rollback failed for candidate %s: %s", candidate.CAID, err)
		return PromotionResult{State: PromotionFailed, Candidate: candidate}, fmt.Errorf("%w; rollback failed: %v", cause, err)
	}
	return PromotionResult{State: PromotionRollingBack, Candidate: candidate}, cause
}
