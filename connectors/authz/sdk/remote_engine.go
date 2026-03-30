package sdk

import (
	"context"
	"fmt"

	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/core"
)

// RemoteEngine implements core.AuthzEngine by forwarding requests to a remote authz service via HTTP
type RemoteEngine struct {
	client *Client
}

// NewRemoteEngine creates a new remote authorization engine that forwards calls to an authz service
// This allows using the authz middleware in external projects without direct database access
func NewRemoteEngine(client *Client) core.AuthzEngine {
	if client == nil {
		panic("client cannot be nil")
	}
	return &RemoteEngine{
		client: client,
	}
}

// Authorize checks if a principal is authorized to perform an action on an entity
// by forwarding the request to the remote authz service
func (r *RemoteEngine) Authorize(principalID, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error) {
	ctx := context.Background()

	req := &dto.AuthorizeRequest{
		PrincipalID: principalID,
		Namespace:   namespace,
		SchemaName:  schemaName,
		Action:      action,
		EntityType:  entityType,
		EntityKey:   dto.NewFlexEntityKeyFromMap(entityKey),
	}

	resp, err := r.client.Authz.Authorize(ctx, req)
	if err != nil {
		return false, fmt.Errorf("remote authorize failed: %w", err)
	}

	return resp.Allowed, nil
}

// GetFilter retrieves a SQL filter for list operations
// by forwarding the request to the remote authz service
func (r *RemoteEngine) GetFilter(principalID, namespace, schemaName, entityType string) (string, error) {
	ctx := context.Background()

	req := &dto.GetFilterRequest{
		PrincipalID: principalID,
		Namespace:   namespace,
		SchemaName:  schemaName,
		EntityType:  entityType,
	}

	resp, err := r.client.Authz.GetFilter(ctx, req)
	if err != nil {
		return "", fmt.Errorf("remote get filter failed: %w", err)
	}

	// Return the where clause (args are not used for simple string filters yet)
	return resp.FilterQuery, nil
}

// MatchAndAuthorize checks authorization using authentication material
// to automatically match and authorize principal(s)
func (r *RemoteEngine) MatchAndAuthorize(authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, []string, error) {
	ctx := context.Background()

	req := &dto.MatchAndAuthorizeRequest{
		AuthMaterial: authMaterial,
		AuthType:     authType,
		Namespace:    namespace,
		SchemaName:   schemaName,
		Action:       action,
		EntityType:   entityType,
		EntityKey:    dto.NewFlexEntityKeyFromMap(entityKey),
	}

	resp, err := r.client.Authz.MatchAndAuthorize(ctx, req)
	if err != nil {
		return false, nil, fmt.Errorf("remote match and authorize failed: %w", err)
	}

	return resp.Allowed, resp.MatchedPrincipals, nil
}

// MatchAndGetFilter retrieves a SQL filter using authentication material
// to automatically match principal(s) and generate the appropriate filter
func (r *RemoteEngine) MatchAndGetFilter(authType, authMaterial, namespace, schemaName, entityType string) (string, []string, error) {
	ctx := context.Background()

	req := &dto.MatchAndGetFilterRequest{
		AuthMaterial: authMaterial,
		AuthType:     authType,
		Namespace:    namespace,
		SchemaName:   schemaName,
		EntityType:   entityType,
	}

	resp, err := r.client.Authz.MatchAndGetFilter(ctx, req)
	if err != nil {
		return "", nil, fmt.Errorf("remote match and get filter failed: %w", err)
	}

	return resp.FilterQuery, resp.MatchedPrincipals, nil
}
