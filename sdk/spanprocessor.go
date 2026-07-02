package sdk

import (
	"context"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type authContextSpanProcessor struct{}

func (authContextSpanProcessor) OnStart(parent context.Context, s sdktrace.ReadWriteSpan) {
	if id, ok := parent.Value(core.LamassuContextKeyAuthID).(string); ok && id != "" {
		s.SetAttributes(attribute.String("enduser.id", id))
	}
	if t, ok := parent.Value(core.LamassuContextKeyAuthType).(string); ok && t != "" {
		s.SetAttributes(attribute.String("enduser.auth_type", t))
	}
	if principals, ok := parent.Value(core.LamassuContextKeyMatchedPrincipals).([]string); ok && len(principals) > 0 {
		s.SetAttributes(attribute.StringSlice("enduser.principals", principals))
	}
}

func (authContextSpanProcessor) OnEnd(sdktrace.ReadOnlySpan)         {}
func (authContextSpanProcessor) Shutdown(context.Context) error       { return nil }
func (authContextSpanProcessor) ForceFlush(context.Context) error     { return nil }
