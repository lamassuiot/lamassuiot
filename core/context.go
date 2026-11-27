package core

import (
	"context"
	"errors"
	"strings"
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
	LamassuContextKeyTenantID          string = "lamassu.io/ctx/tenant-id"
)

// ErrMissingTenantID is returned by RequireTenantID when no tenant_id is present in context.
var ErrMissingTenantID = errors.New("missing tenant_id in context")

// WithTenantID returns a derived context carrying a trimmed non-empty tenant_id.
// If tenantID is empty/whitespace, ctx is returned unchanged.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ctx
	}
	return context.WithValue(ctx, LamassuContextKeyTenantID, tenantID)
}

// TenantIDFromContext retrieves the tenant_id from ctx, if present and non-empty.
func TenantIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	tenantID, ok := ctx.Value(LamassuContextKeyTenantID).(string)
	tenantID = strings.TrimSpace(tenantID)
	return tenantID, ok && tenantID != ""
}

// RequireTenantID returns the tenant_id from ctx or ErrMissingTenantID if absent.
func RequireTenantID(ctx context.Context) (string, error) {
	tenantID, ok := TenantIDFromContext(ctx)
	if !ok {
		return "", ErrMissingTenantID
	}
	return tenantID, nil
}
