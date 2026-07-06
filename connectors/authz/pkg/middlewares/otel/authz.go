package otelmw
package otelmw

import (
	"context"

	"github.com/lamassuiot/authz/pkg/core"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/lamassuiot/authz"

// AuthzOTelMiddleware wraps a core.AuthzEngine and creates an OTEL span for every
// authorization call, recording the decision outcome and key request attributes.
type AuthzOTelMiddleware struct {
	next core.AuthzEngine
}

// NewAuthzOTelMiddleware returns a core.AuthzEngine that wraps next with OTEL tracing.
func NewAuthzOTelMiddleware(next core.AuthzEngine) core.AuthzEngine {
	return &AuthzOTelMiddleware{next: next}
}

func (mw *AuthzOTelMiddleware) Authorize(ctx context.Context, principalID, namespace, schemaName, action, entityType string, entityKey map[string]string) (allowed bool, err error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "authz.Authorize",
		trace.WithAttributes(
			attribute.String("authz.principal_id", principalID),
			attribute.String("authz.namespace", namespace),
			attribute.String("authz.schema", schemaName),
			attribute.String("authz.action", action),
			attribute.String("authz.entity_type", entityType),
		),
	)
	defer func() {
		span.SetAttributes(attribute.Bool("authz.allowed", allowed))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	return mw.next.Authorize(ctx, principalID, namespace, schemaName, action, entityType, entityKey)
}

func (mw *AuthzOTelMiddleware) GetFilter(ctx context.Context, principalID, namespace, schemaName, entityType string) (_ string, err error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "authz.GetFilter",
		trace.WithAttributes(
			attribute.String("authz.principal_id", principalID),
			attribute.String("authz.namespace", namespace),
			attribute.String("authz.schema", schemaName),
			attribute.String("authz.entity_type", entityType),
		),
	)
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	return mw.next.GetFilter(ctx, principalID, namespace, schemaName, entityType)
}

func (mw *AuthzOTelMiddleware) MatchAndAuthorize(ctx context.Context, authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (allowed bool, principals []string, err error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "authz.MatchAndAuthorize",
		trace.WithAttributes(
			attribute.String("authz.auth_type", authType),
			attribute.String("authz.namespace", namespace),
			attribute.String("authz.schema", schemaName),
			attribute.String("authz.action", action),
			attribute.String("authz.entity_type", entityType),
		),
	)
	defer func() {
		span.SetAttributes(
			attribute.Bool("authz.allowed", allowed),
			attribute.Int("authz.matched_principal_count", len(principals)),
		)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	return mw.next.MatchAndAuthorize(ctx, authType, authMaterial, namespace, schemaName, action, entityType, entityKey)
}

func (mw *AuthzOTelMiddleware) MatchAndGetFilter(ctx context.Context, authType, authMaterial, namespace, schemaName, entityType string) (_ string, principals []string, err error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "authz.MatchAndGetFilter",
		trace.WithAttributes(
			attribute.String("authz.auth_type", authType),
			attribute.String("authz.namespace", namespace),
			attribute.String("authz.schema", schemaName),
			attribute.String("authz.entity_type", entityType),
		),
	)
	defer func() {
		span.SetAttributes(attribute.Int("authz.matched_principal_count", len(principals)))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	return mw.next.MatchAndGetFilter(ctx, authType, authMaterial, namespace, schemaName, entityType)
}
