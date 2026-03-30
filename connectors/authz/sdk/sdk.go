package sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lamassuiot/authz/pkg/api/dto"
	"github.com/lamassuiot/authz/pkg/authz"
)

// ClientConfig holds configuration for the SDK client
type ClientConfig struct {
	BaseURL            string
	TLSConfig          *tls.Config
	InsecureSkipVerify bool
	Timeout            time.Duration
	CustomHeaders      map[string]string
}

// DefaultConfig returns a default client configuration
func DefaultConfig(baseURL string) *ClientConfig {
	return &ClientConfig{
		BaseURL:            baseURL,
		TLSConfig:          &tls.Config{},
		InsecureSkipVerify: false,
		Timeout:            30 * time.Second,
		CustomHeaders:      make(map[string]string),
	}
}

// Client is the main SDK client for the authz API
type Client struct {
	httpClient *http.Client
	baseURL    string
	headers    map[string]string

	// Service clients
	Authz      AuthzService
	Principals PrincipalService
	Policies   PolicyService
	Schemas    SchemaService
}

// NewClient creates a new SDK client
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	if config.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	client := &Client{
		httpClient: httpClient,
		baseURL:    config.BaseURL,
		headers:    config.CustomHeaders,
	}

	// Initialize service clients
	client.Authz = newAuthzClient(client)
	client.Principals = newPrincipalClient(client)
	client.Policies = newPolicyClient(client)
	client.Schemas = newSchemaClient(client)

	return client, nil
}

// WithHeader adds a custom header to all requests
func (c *Client) WithHeader(key, value string) *Client {
	if c.headers == nil {
		c.headers = make(map[string]string)
	}
	c.headers[key] = value
	return c
}

// HTTP utility methods

func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, "GET", path, nil, result)
}

func (c *Client) post(ctx context.Context, path string, body interface{}, result interface{}) error {
	return c.doRequest(ctx, "POST", path, body, result)
}

func (c *Client) put(ctx context.Context, path string, body interface{}, result interface{}) error {
	return c.doRequest(ctx, "PUT", path, body, result)
}

func (c *Client) delete(ctx context.Context, path string) error {
	return c.doRequest(ctx, "DELETE", path, nil, nil)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	fullURL := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle error responses
	if resp.StatusCode >= 400 {
		var errResp dto.ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    errResp.Error,
			Details:    errResp.Details,
		}
	}

	// Handle success responses
	if result != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// APIError represents an error from the API
type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]string
}

func (e *APIError) Error() string {
	if len(e.Details) > 0 {
		detailsJSON, _ := json.Marshal(e.Details)
		return fmt.Sprintf("API error (HTTP %d): %s - %s", e.StatusCode, e.Message, string(detailsJSON))
	}
	return fmt.Sprintf("API error (HTTP %d): %s", e.StatusCode, e.Message)
}

// AuthzService handles authorization operations
type AuthzService interface {
	Authorize(ctx context.Context, req *dto.AuthorizeRequest) (*dto.AuthorizeResponse, error)
	GetFilter(ctx context.Context, req *dto.GetFilterRequest) (*dto.GetFilterResponse, error)
	MatchAndAuthorize(ctx context.Context, req *dto.MatchAndAuthorizeRequest) (*dto.MatchAndAuthorizeResponse, error)
	MatchAndGetFilter(ctx context.Context, req *dto.MatchAndGetFilterRequest) (*dto.MatchAndGetFilterResponse, error)
}

type authzClient struct {
	client *Client
}

func newAuthzClient(client *Client) AuthzService {
	return &authzClient{client: client}
}

func (s *authzClient) Authorize(ctx context.Context, req *dto.AuthorizeRequest) (*dto.AuthorizeResponse, error) {
	var result dto.AuthorizeResponse
	err := s.client.post(ctx, "/v1/authz/authorize", req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *authzClient) GetFilter(ctx context.Context, req *dto.GetFilterRequest) (*dto.GetFilterResponse, error) {
	var result dto.GetFilterResponse
	err := s.client.post(ctx, "/v1/authz/filter", req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *authzClient) MatchAndAuthorize(ctx context.Context, req *dto.MatchAndAuthorizeRequest) (*dto.MatchAndAuthorizeResponse, error) {
	var result dto.MatchAndAuthorizeResponse
	err := s.client.post(ctx, "/v1/authz/match/authorize", req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *authzClient) MatchAndGetFilter(ctx context.Context, req *dto.MatchAndGetFilterRequest) (*dto.MatchAndGetFilterResponse, error) {
	var result dto.MatchAndGetFilterResponse
	err := s.client.post(ctx, "/v1/authz/match/filter", req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// PrincipalService handles principal management operations
type PrincipalService interface {
	Create(ctx context.Context, req *dto.CreatePrincipalRequest) (*dto.PrincipalResponse, error)
	Get(ctx context.Context, id string) (*dto.PrincipalResponse, error)
	List(ctx context.Context, activeOnly bool) (*dto.ListPrincipalsResponse, error)
	Update(ctx context.Context, id string, req *dto.UpdatePrincipalRequest) (*dto.PrincipalResponse, error)
	Delete(ctx context.Context, id string) error
	GetPolicies(ctx context.Context, id string) (*dto.ListPrincipalPoliciesResponse, error)
	GrantPolicy(ctx context.Context, id string, req *dto.GrantPolicyRequest) error
	RevokePolicy(ctx context.Context, id string, policyID string) error
}

type principalClient struct {
	client *Client
}

func newPrincipalClient(client *Client) PrincipalService {
	return &principalClient{client: client}
}

func (s *principalClient) Create(ctx context.Context, req *dto.CreatePrincipalRequest) (*dto.PrincipalResponse, error) {
	var result dto.PrincipalResponse
	err := s.client.post(ctx, "/v1/principals", req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *principalClient) Get(ctx context.Context, id string) (*dto.PrincipalResponse, error) {
	var result dto.PrincipalResponse
	err := s.client.get(ctx, fmt.Sprintf("/v1/principals/%s", url.PathEscape(id)), &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *principalClient) List(ctx context.Context, activeOnly bool) (*dto.ListPrincipalsResponse, error) {
	path := "/v1/principals"
	if activeOnly {
		path += "?activeOnly=true"
	}
	var result dto.ListPrincipalsResponse
	err := s.client.get(ctx, path, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *principalClient) Update(ctx context.Context, id string, req *dto.UpdatePrincipalRequest) (*dto.PrincipalResponse, error) {
	var result dto.PrincipalResponse
	err := s.client.put(ctx, fmt.Sprintf("/v1/principals/%s", url.PathEscape(id)), req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *principalClient) Delete(ctx context.Context, id string) error {
	return s.client.delete(ctx, fmt.Sprintf("/v1/principals/%s", url.PathEscape(id)))
}

func (s *principalClient) GetPolicies(ctx context.Context, id string) (*dto.ListPrincipalPoliciesResponse, error) {
	var result dto.ListPrincipalPoliciesResponse
	err := s.client.get(ctx, fmt.Sprintf("/v1/principals/%s/policies", url.PathEscape(id)), &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *principalClient) GrantPolicy(ctx context.Context, id string, req *dto.GrantPolicyRequest) error {
	return s.client.post(ctx, fmt.Sprintf("/v1/principals/%s/policies", url.PathEscape(id)), req, nil)
}

func (s *principalClient) RevokePolicy(ctx context.Context, id string, policyID string) error {
	return s.client.delete(ctx, fmt.Sprintf("/v1/principals/%s/policies/%s", url.PathEscape(id), url.PathEscape(policyID)))
}

// PolicyService handles policy management operations
type PolicyService interface {
	Create(ctx context.Context, req *dto.CreatePolicyRequest) (*dto.PolicyResponse, error)
	Get(ctx context.Context, id string) (*dto.PolicyResponse, error)
	List(ctx context.Context) (*dto.PolicyListResponse, error)
	Update(ctx context.Context, id string, req *dto.UpdatePolicyRequest) (*dto.PolicyResponse, error)
	Delete(ctx context.Context, id string) error
	GetStats(ctx context.Context, id string) (*dto.PolicyStatsResponse, error)
}

type policyClient struct {
	client *Client
}

func newPolicyClient(client *Client) PolicyService {
	return &policyClient{client: client}
}

func (s *policyClient) Create(ctx context.Context, req *dto.CreatePolicyRequest) (*dto.PolicyResponse, error) {
	var result dto.PolicyResponse
	err := s.client.post(ctx, "/v1/policies", req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *policyClient) Get(ctx context.Context, id string) (*dto.PolicyResponse, error) {
	var result dto.PolicyResponse
	err := s.client.get(ctx, fmt.Sprintf("/v1/policies/%s", url.PathEscape(id)), &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *policyClient) List(ctx context.Context) (*dto.PolicyListResponse, error) {
	var result dto.PolicyListResponse
	err := s.client.get(ctx, "/v1/policies", &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *policyClient) Update(ctx context.Context, id string, req *dto.UpdatePolicyRequest) (*dto.PolicyResponse, error) {
	var result dto.PolicyResponse
	err := s.client.put(ctx, fmt.Sprintf("/v1/policies/%s", url.PathEscape(id)), req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *policyClient) Delete(ctx context.Context, id string) error {
	return s.client.delete(ctx, fmt.Sprintf("/v1/policies/%s", url.PathEscape(id)))
}

func (s *policyClient) GetStats(ctx context.Context, id string) (*dto.PolicyStatsResponse, error) {
	var result dto.PolicyStatsResponse
	err := s.client.get(ctx, fmt.Sprintf("/v1/policies/%s/stats", url.PathEscape(id)), &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// SchemaService handles schema operations
type SchemaService interface {
	GetSchemas(ctx context.Context) (map[string]*authz.SchemaDefinition, error)
}

type schemaClient struct {
	client *Client
}

func newSchemaClient(client *Client) SchemaService {
	return &schemaClient{client: client}
}

func (s *schemaClient) GetSchemas(ctx context.Context) (map[string]*authz.SchemaDefinition, error) {
	var result map[string]*authz.SchemaDefinition
	err := s.client.get(ctx, "/v1/schemas", &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
