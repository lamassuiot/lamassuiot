package core

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
)

const (
	LamassuContextKeyAuthID               string = "lamassu.io/ctx/auth-id"
	LamassuContextKeyAuthCredentialString string = "lamassu.io/ctx/auth-credential-string"
	LamassuContextKeyAuthCredentialStruct string = "lamassu.io/ctx/auth-credential-struct"
	LamassuContextKeyAuthContext          string = "lamassu.io/ctx/auth-context"
	LamassuContextKeyAuthType             string = "lamassu.io/ctx/auth-type"
	LamassuContextKeyRequestID            string = "lamassu.io/ctx/request-id"
	LamassuContextKeySource               string = "lamassu.io/ctx/source"
	LamassuContextKeyHTTPRequest          string = "lamassu.io/ctx/http-request"

	LamassuContextKeyEventType    string = "lamassu.io/ctx/cloudevent/type"
	LamassuContextKeyEventSubject string = "lamassu.io/ctx/cloudevent/subject"

	LamassuContextKeyMatchedPrincipals string = "lamassu.io/ctx/matched-principals"
)

type contextKey string

const tenantContextKey contextKey = "lamassu.io/ctx/tenant"

type TenantStatus = models.TenantStatus

const (
	TenantActive    = models.TenantActive
	TenantSuspended = models.TenantSuspended
)

var (
	ErrTenantContextRequired      = errors.New("tenant context is required")
	ErrTenantContextInvalid       = errors.New("tenant context is invalid")
	ErrTenantResourceAccessDenied = errors.New("tenant resource access denied")
)

type TenantContext struct {
	OrganizationID string
	TenantID       string
	ActorID        string
	ActorType      string
	EffectiveRole  models.TenantRole
	Permissions    []string
	CorrelationID  string
	Source         string
	TenantStatus   TenantStatus
	Validated      bool
}

func (tenantContext TenantContext) Validate() error {
	if tenantContext.OrganizationID == "" || tenantContext.TenantID == "" {
		return fmt.Errorf("%w: organization and tenant are required", ErrTenantContextInvalid)
	}
	if tenantContext.ActorID == "" || tenantContext.ActorType == "" {
		return fmt.Errorf("%w: actor is required", ErrTenantContextInvalid)
	}
	if tenantContext.CorrelationID == "" || tenantContext.Source == "" {
		return fmt.Errorf("%w: correlation and source are required", ErrTenantContextInvalid)
	}
	if !tenantContext.Validated {
		return fmt.Errorf("%w: context has not been validated", ErrTenantContextInvalid)
	}
	if tenantContext.TenantStatus == TenantSuspended {
		return fmt.Errorf("%w: tenant is not active", ErrTenantContextInvalid)
	}
	return nil
}

func NewValidatedTenantContext(membership models.Membership, tenant models.Tenant, actorID, actorType string, permissions []string, correlationID, source string) (TenantContext, error) {
	if membership.OrganizationID != tenant.OrganizationID || membership.TenantID != tenant.ID {
		return TenantContext{}, ErrTenantResourceAccessDenied
	}
	if membership.Status != models.MembershipActive || tenant.Status != models.TenantActive {
		return TenantContext{}, ErrTenantResourceAccessDenied
	}
	tenantContext := TenantContext{
		OrganizationID: tenant.OrganizationID,
		TenantID:       tenant.ID,
		ActorID:        actorID,
		ActorType:      actorType,
		EffectiveRole:  membership.Role,
		Permissions:    append([]string(nil), permissions...),
		CorrelationID:  correlationID,
		Source:         source,
		TenantStatus:   tenant.Status,
		Validated:      true,
	}
	if err := tenantContext.Validate(); err != nil {
		return TenantContext{}, err
	}
	return tenantContext, nil
}

func CanonicalActorID(issuer, subject string) string {
	encodedIssuer := base64.RawURLEncoding.EncodeToString([]byte(issuer))
	encodedSubject := base64.RawURLEncoding.EncodeToString([]byte(subject))
	return encodedIssuer + "." + encodedSubject
}

func WithTenantContext(ctx context.Context, tenantContext TenantContext) context.Context {
	return context.WithValue(ctx, tenantContextKey, tenantContext)
}

func TenantContextFromContext(ctx context.Context) (TenantContext, error) {
	if ctx == nil {
		return TenantContext{}, ErrTenantContextRequired
	}
	tenantContext, ok := ctx.Value(tenantContextKey).(TenantContext)
	if !ok {
		return TenantContext{}, ErrTenantContextRequired
	}
	return tenantContext, nil
}

func RequireTenantContext(ctx context.Context) (TenantContext, error) {
	tenantContext, err := TenantContextFromContext(ctx)
	if err != nil {
		return TenantContext{}, err
	}
	if err := tenantContext.Validate(); err != nil {
		return TenantContext{}, err
	}
	return tenantContext, nil
}
