package sdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestClientWithHTTPClientKeepsTheCallersTransport(t *testing.T) {
	var gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Principal-ID")
		_, _ = w.Write([]byte(`{"id":"dms:ra-1"}`))
	}))
	defer server.Close()

	httpClient := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Principal-ID", "admin-mode")
		return http.DefaultTransport.RoundTrip(r)
	})}
	principal, err := NewClientWithHTTPClient(httpClient, server.URL).Principals.Get(context.Background(), "dms:ra-1")

	require.NoError(t, err)
	assert.Equal(t, "dms:ra-1", principal.ID)
	assert.Equal(t, "admin-mode", gotHeader)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
