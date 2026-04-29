package core

import "context"

type AuthzEngine interface {
	Authorize(ctx context.Context, principalID, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error)
	GetFilter(ctx context.Context, principalID, namespace, schemaName, entityType string) (string, error)
	MatchAndAuthorize(ctx context.Context, authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, []string, error)
	MatchAndGetFilter(ctx context.Context, authType, authMaterial, namespace, schemaName, entityType string) (string, []string, error)
}
