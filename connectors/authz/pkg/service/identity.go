package service

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/models"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// noMatchError is returned when auth material matches no active principals.
// It implements HTTPStatusCode() so the gin middleware maps it to 401.
type noMatchError struct{}

func (noMatchError) Error() string       { return "no matching principals found" }
func (noMatchError) HTTPStatusCode() int { return http.StatusUnauthorized }
func (noMatchError) Is(target error) bool {
	_, ok := target.(noMatchError)
	return ok
}

// ErrNoMatch is returned by IdentityResolver when auth material matches no active principals.
var ErrNoMatch error = noMatchError{}

// IdentityResolver is the single entry point for the "match auth material → load policies" flow.
type IdentityResolver struct {
	match    principalMatcher
	grants   engine.GrantStore
	policies policyLoader
}

// principalMatcher is the local interface for the MatchService.
type principalMatcher interface {
	MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error)
}

type subjectMatcher interface {
	MatchSubjects(ctx context.Context, authMaterial interface{}, authType string) ([]engine.ResolvedSubject, error)
}

// policyLoader is the local interface for PolicyManager used by IdentityResolver.
type policyLoader interface {
	GetPolicy(ctx context.Context, policyID string) (*models.Policy, error)
}

// NewIdentityResolver wires a MatchService, GrantStore, and PolicyManager into a resolver.
func NewIdentityResolver(match principalMatcher, grants engine.GrantStore, policies policyLoader) *IdentityResolver {
	return &IdentityResolver{match: match, grants: grants, policies: policies}
}

// loadGrantedPolicies fetches each policy referenced by grants and registers it in registry.
func (r *IdentityResolver) loadGrantedPolicies(ctx context.Context, registry *engine.PolicyRegistry, grants []models.PrincipalPolicy) error {
	ctx, span := otel.Tracer(models.OtelTracerName).Start(ctx, "authz.policy.load",
		trace.WithAttributes(attribute.Int("authz.grant_count", len(grants))),
	)
	loaded := 0
	defer func() {
		span.SetAttributes(attribute.Int("authz.policy_loaded_count", loaded))
		span.End()
	}()
	for _, g := range grants {
		policy, err := r.policies.GetPolicy(ctx, g.PolicyID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("load policy %s: %w", g.PolicyID, err)
		}
		if err := registry.AddPolicy(policy); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("register policy %s: %w", g.PolicyID, err)
		}
		loaded++
	}
	return nil
}

// Resolve matches auth material to active principals, loads all their granted policies,
// and returns a populated PolicyRegistry ready for Engine.Authorize or Engine.GetListFilter.
// Returns ErrNoMatch (check with errors.Is) when no principals matched.
func (r *IdentityResolver) Resolve(ctx context.Context, authMaterial interface{}, authType string) (*engine.PolicyRegistry, []string, error) {
	matchCtx, matchSpan := otel.Tracer(models.OtelTracerName).Start(ctx, "authz.principal.match",
		trace.WithAttributes(attribute.String("authz.auth_type", authType)),
	)
	principalIDs, err := r.match.MatchPrincipals(matchCtx, authMaterial, authType)
	matchSpan.SetAttributes(attribute.Int("authz.matched_count", len(principalIDs)))
	if err != nil {
		matchSpan.RecordError(err)
		matchSpan.SetStatus(codes.Error, err.Error())
		matchSpan.End()
		return nil, nil, fmt.Errorf("match principals: %w", err)
	}
	matchSpan.End()

	if len(principalIDs) == 0 {
		return nil, nil, ErrNoMatch
	}

	registry := engine.NewPolicyRegistry()
	for _, pid := range principalIDs {
		grants, _, err := r.grants.ListForPrincipal(ctx, pid, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("get policies for principal %s: %w", pid, err)
		}
		if err := r.loadGrantedPolicies(ctx, registry, grants); err != nil {
			return nil, nil, err
		}
	}
	return registry, principalIDs, nil
}

// ResolveSubjects matches auth material to active subjects and loads policies
// separately for each subject. This is used by HTTP authorization so policy
// grants cannot be merged across subjects before route constraints are checked.
func (r *IdentityResolver) ResolveSubjects(ctx context.Context, authMaterial interface{}, authType string) ([]engine.SubjectPolicySet, []string, error) {
	var subjects []engine.ResolvedSubject
	if matcher, ok := r.match.(subjectMatcher); ok {
		matchCtx, matchSpan := otel.Tracer(models.OtelTracerName).Start(ctx, "authz.principal.match",
			trace.WithAttributes(
				attribute.String("authz.auth_type", authType),
				attribute.String("authz.match_mode", "subject"),
			),
		)
		matchedSubjects, err := matcher.MatchSubjects(matchCtx, authMaterial, authType)
		matchSpan.SetAttributes(attribute.Int("authz.matched_count", len(matchedSubjects)))
		if err != nil {
			matchSpan.RecordError(err)
			matchSpan.SetStatus(codes.Error, err.Error())
			matchSpan.End()
			return nil, nil, fmt.Errorf("match subjects: %w", err)
		}
		matchSpan.End()
		subjects = matchedSubjects
	} else {
		matchCtx, matchSpan := otel.Tracer(models.OtelTracerName).Start(ctx, "authz.principal.match",
			trace.WithAttributes(
				attribute.String("authz.auth_type", authType),
				attribute.String("authz.match_mode", "principal"),
			),
		)
		principalIDs, err := r.match.MatchPrincipals(matchCtx, authMaterial, authType)
		matchSpan.SetAttributes(attribute.Int("authz.matched_count", len(principalIDs)))
		if err != nil {
			matchSpan.RecordError(err)
			matchSpan.SetStatus(codes.Error, err.Error())
			matchSpan.End()
			return nil, nil, fmt.Errorf("match principals: %w", err)
		}
		matchSpan.End()
		subjects = make([]engine.ResolvedSubject, 0, len(principalIDs))
		for _, principalID := range principalIDs {
			subjects = append(subjects, engine.ResolvedSubject{
				PrincipalID: principalID,
				Attributes:  map[string]string{},
			})
		}
	}

	if len(subjects) == 0 {
		return nil, nil, ErrNoMatch
	}

	subjectPolicies := make([]engine.SubjectPolicySet, 0, len(subjects))
	principalIDs := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		if subject.Attributes == nil {
			subject.Attributes = map[string]string{}
		}
		registry := engine.NewPolicyRegistry()
		grants, _, err := r.grants.ListForPrincipal(ctx, subject.PrincipalID, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("get policies for principal %s: %w", subject.PrincipalID, err)
		}
		if err := r.loadGrantedPolicies(ctx, registry, grants); err != nil {
			return nil, nil, err
		}
		subjectPolicies = append(subjectPolicies, engine.SubjectPolicySet{
			Subject:  subject,
			Policies: registry,
		})
		principalIDs = append(principalIDs, subject.PrincipalID)
	}
	return subjectPolicies, principalIDs, nil
}

// GetPoliciesForPrincipal loads policies for a single known principal ID and returns
// a populated PolicyRegistry. Used by the by-ID authorization path.
func (r *IdentityResolver) GetPoliciesForPrincipal(ctx context.Context, principalID string) (reg *engine.PolicyRegistry, err error) {
	ctx, span := otel.Tracer(models.OtelTracerName).Start(ctx, "authz.policy.load_for_principal",
		trace.WithAttributes(attribute.String("authz.principal_id", principalID)),
	)
	defer func() {
		if reg != nil {
			span.SetAttributes(attribute.Int("authz.policy_count", len(reg.GetAll())))
		}
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	var grants []models.PrincipalPolicy
	grants, _, err = r.grants.ListForPrincipal(ctx, principalID, nil)
	if err != nil {
		return nil, fmt.Errorf("get policies for principal %s: %w", principalID, err)
	}

	reg = engine.NewPolicyRegistry()
	if err = r.loadGrantedPolicies(ctx, reg, grants); err != nil {
		return nil, err
	}
	return reg, nil
}

// MatchPrincipals delegates to the underlying MatchService. Useful for callers that need
// the principal IDs without loading policies (e.g. capabilities controller).
func (r *IdentityResolver) MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error) {
	return r.match.MatchPrincipals(ctx, authMaterial, authType)
}
