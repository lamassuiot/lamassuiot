package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	lamassucore "github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientPreservesStatusForNonJSONErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := NewClient(DefaultConfig(server.URL, ""))
	require.NoError(t, err)

	err = client.get(context.Background(), "/v1/authz/match/authorize", nil)
	require.Error(t, err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusUnauthorized, apiErr.HTTPStatusCode())
}

func TestRemoteEnginePropagatesTenantIDInRequests(t *testing.T) {
	received := map[string]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		received[r.URL.Path] = body
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/authz/match/authorize":
			_, _ = w.Write([]byte(`{"allowed":true,"matched_principals":["p1"]}`))
		case "/v1/authz/match/filter":
			_, _ = w.Write([]byte(`{"filter_query":"SELECT * FROM ca.ca_certificates","matched_principals":["p1"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewClient(DefaultConfig(server.URL, "ca"))
	require.NoError(t, err)
	engine := NewRemoteEngine(client)

	ctx := context.WithValue(context.Background(), lamassucore.LamassuContextKeyTenantID, "tenant-42")

	allowed, principals, err := engine.MatchAndAuthorize(ctx, "oidc", "jwt-token", "pki", "ca", "read", "ca_certificate", map[string]string{"id": "ca-1"})
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, []string{"p1"}, principals)
	assert.Equal(t, "tenant-42", received["/v1/authz/match/authorize"]["tenant_id"])

	filter, principals, err := engine.MatchAndGetFilter(ctx, "oidc", "jwt-token", "pki", "ca", "ca_certificate")
	require.NoError(t, err)
	assert.NotEmpty(t, filter)
	assert.Equal(t, []string{"p1"}, principals)
	assert.Equal(t, "tenant-42", received["/v1/authz/match/filter"]["tenant_id"])
}
