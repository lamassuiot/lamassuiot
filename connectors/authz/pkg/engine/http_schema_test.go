package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPSchemaRegistry_LoadGroupedRoutes(t *testing.T) {
	registry := NewHTTPSchemaRegistry()
	schemaPath := writeHTTPSchemaTestFile(t, `[
		{
			"name": "svc",
			"groups": [
				{
					"name": "System Group",
					"routes": [
						{
							"name": "status-read",
							"methods": ["GET"],
							"path": "/api/v1/status",
							"match_type": "exact",
							"action": "status-read"
						}
					]
				},
				{
					"name": "Workflow Group",
					"routes": [
						{
							"name": "workflow-read",
							"methods": ["GET"],
							"path": "^/api/v1/workflows/[^/]+$",
							"match_type": "regex",
							"action": "workflow-read"
						},
						{
							"name": "workflow-delete",
							"methods": ["DELETE"],
							"path": "^/api/v1/workflows/[^/]+$",
							"match_type": "regex",
							"action": "workflow-delete"
						}
					]
				}
			]
		}
	]`)

	require.NoError(t, registry.Load(schemaPath))
	schema, err := registry.Get("svc")
	require.NoError(t, err)

	require.Len(t, schema.Groups, 2)
	assert.Empty(t, schema.Routes)
	assert.ElementsMatch(t, []string{"status-read", "workflow-read", "workflow-delete"}, schema.AllActions)
	assert.ElementsMatch(t, []string{"workflow-read", "workflow-delete"}, schema.Groups[1].AllActions)

	route := schema.MatchRoute("GET", "/api/v1/workflows/workflow-1")
	require.NotNil(t, route)
	assert.Equal(t, "workflow-read", route.Action)
	assert.Nil(t, schema.MatchRoute("POST", "/api/v1/workflows/workflow-1"))
}

func TestHTTPSchemaRegistry_LoadWFXExampleGroups(t *testing.T) {
	registry := NewHTTPSchemaRegistry()
	require.NoError(t, registry.Load("../../examples/wfx/wfx.json"))

	schema, err := registry.Get("Job Manager")
	require.NoError(t, err)

	require.Len(t, schema.Groups, 6)
	assert.Equal(t, "Mgmt NBI System", schema.Groups[0].Name)
	assert.Len(t, schema.Groups[0].Routes, 2)
	assert.Equal(t, "Mgmt NBI Workflows", schema.Groups[1].Name)
	assert.Len(t, schema.Groups[1].Routes, 4)
	assert.Equal(t, "Mgmt NBI Jobs", schema.Groups[2].Name)
	assert.Len(t, schema.Groups[2].Routes, 12)
	assert.Equal(t, "Device SBI System", schema.Groups[3].Name)
	assert.Len(t, schema.Groups[3].Routes, 2)
	assert.Equal(t, "Device SBI Workflows", schema.Groups[4].Name)
	assert.Len(t, schema.Groups[4].Routes, 2)
	assert.Equal(t, "Device SBI Jobs", schema.Groups[5].Name)
	assert.Len(t, schema.Groups[5].Routes, 8)
	assert.NotContains(t, schema.AllActions, "system")
	assert.NotContains(t, schema.AllActions, "workflow")
	assert.NotContains(t, schema.AllActions, "job")
	assert.Contains(t, schema.AllActions, "nbi-job-delete")
	assert.Contains(t, schema.AllActions, "sbi-job-status-update")

	route := schema.MatchRoute("DELETE", "/api/wfx/nbi/v1/jobs/job-1")
	require.NotNil(t, route)
	assert.Equal(t, "nbi-job-delete", route.Action)

	route = schema.MatchRoute("PUT", "/api/wfx/sbi/v1/jobs/job-1/status")
	require.NotNil(t, route)
	assert.Equal(t, "sbi-job-status-update", route.Action)
	assert.Len(t, route.Constraints, 1)
	assert.Nil(t, schema.MatchRoute("POST", "/api/wfx/sbi/v1/jobs"))
}

func TestEngineCheckHTTP_WFXNBISBIActionsAreDistinct(t *testing.T) {
	eng, err := NewEngine(nil, nil, WithHTTPSchemas([]string{"../../examples/wfx/wfx.json"}))
	require.NoError(t, err)

	sbiPolicies := NewPolicyRegistry()
	require.NoError(t, sbiPolicies.AddPolicy(&models.Policy{
		ID:   "sbi-job-status-update",
		Name: "SBI Job Status Update",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "Job Manager",
				Actions:    []string{"sbi-job-status-update"},
			},
		},
	}))

	result, err := eng.CheckHTTPRequest(context.Background(), HTTPCheckRequest{
		Method: "PUT",
		Path:   "/api/wfx/sbi/v1/jobs/job-1/status",
		Body:   []byte(`{"state":"INSTALLING","clientId":"client-1"}`),
		Subjects: []SubjectPolicySet{
			{
				Subject: ResolvedSubject{
					PrincipalID: "client-1-principal",
					Attributes:  map[string]string{"client_id": "client-1"},
				},
				Policies: sbiPolicies,
			},
		},
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "sbi-job-status-update", result.MatchedPolicyID)

	allowed, policyID, err := eng.CheckHTTP(context.Background(), sbiPolicies, "PUT", "/api/wfx/nbi/v1/jobs/job-1/status")
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.Empty(t, policyID)

	nbiPolicies := NewPolicyRegistry()
	require.NoError(t, nbiPolicies.AddPolicy(&models.Policy{
		ID:   "nbi-job-status-update",
		Name: "NBI Job Status Update",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "Job Manager",
				Actions:    []string{"nbi-job-status-update"},
			},
		},
	}))

	allowed, policyID, err = eng.CheckHTTP(context.Background(), nbiPolicies, "PUT", "/api/wfx/nbi/v1/jobs/job-1/status")
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, "nbi-job-status-update", policyID)
}

func TestEngineCheckHTTPRequest_WFXSBIClientConstraints(t *testing.T) {
	eng, err := NewEngine(nil, nil, WithHTTPSchemas([]string{"../../examples/wfx/wfx.json"}))
	require.NoError(t, err)

	policies := NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{
		ID:   "sbi-device-client",
		Name: "SBI Device Client",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "Job Manager",
				Actions: []string{
					"sbi-job-list",
					"sbi-job-events",
					"sbi-job-read",
					"sbi-job-status-update",
				},
			},
		},
	}))

	subject := SubjectPolicySet{
		Subject: ResolvedSubject{
			PrincipalID: "device-client-42",
			Attributes:  map[string]string{"client_id": "client42"},
		},
		Policies: policies,
	}

	tests := []struct {
		name string
		req  HTTPCheckRequest
		want bool
	}{
		{
			name: "job list requires matching clientId query",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/wfx/sbi/v1/jobs",
				RawQuery: "clientId=client42",
				Subjects: []SubjectPolicySet{subject},
			},
			want: true,
		},
		{
			name: "job list denies missing clientId query",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/wfx/sbi/v1/jobs",
				Subjects: []SubjectPolicySet{subject},
			},
			want: false,
		},
		{
			name: "job events requires matching clientIds query",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/wfx/sbi/v1/jobs/events",
				RawQuery: "clientIds=client42",
				Subjects: []SubjectPolicySet{subject},
			},
			want: true,
		},
		{
			name: "job events denies different clientIds query",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/wfx/sbi/v1/jobs/events",
				RawQuery: "clientIds=other-client",
				Subjects: []SubjectPolicySet{subject},
			},
			want: false,
		},
		{
			name: "job read requires matching x-wfx-client-id header",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/wfx/sbi/v1/jobs/job-1",
				Headers:  map[string]string{"x-wfx-client-id": "client42"},
				Subjects: []SubjectPolicySet{subject},
			},
			want: true,
		},
		{
			name: "job read denies missing x-wfx-client-id header",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/wfx/sbi/v1/jobs/job-1",
				Subjects: []SubjectPolicySet{subject},
			},
			want: false,
		},
		{
			name: "status update requires matching clientId body",
			req: HTTPCheckRequest{
				Method:   "PUT",
				Path:     "/api/wfx/sbi/v1/jobs/job-1/status",
				Body:     []byte(`{"state":"INSTALLING","clientId":"client42"}`),
				Subjects: []SubjectPolicySet{subject},
			},
			want: true,
		},
		{
			name: "status update denies different clientId body",
			req: HTTPCheckRequest{
				Method:   "PUT",
				Path:     "/api/wfx/sbi/v1/jobs/job-1/status",
				Body:     []byte(`{"state":"INSTALLING","clientId":"other-client"}`),
				Subjects: []SubjectPolicySet{subject},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eng.CheckHTTPRequest(context.Background(), tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result.Allowed)
			if tt.want {
				assert.Equal(t, "sbi-device-client", result.MatchedPolicyID)
				assert.Equal(t, "device-client-42", result.MatchedPrincipalID)
			}
		})
	}
}

func TestEngineCheckHTTP_RequiresIndividualRouteActionInGroupedSchema(t *testing.T) {
	schemaPath := writeHTTPSchemaTestFile(t, `[
		{
			"name": "svc",
			"groups": [
				{
					"name": "System Group",
					"routes": [
						{
							"name": "status-read",
							"methods": ["GET"],
							"path": "/api/v1/status",
							"match_type": "exact",
							"action": "status-read"
						}
					]
				},
				{
					"name": "Workflow Group",
					"routes": [
						{
							"name": "workflow-read",
							"methods": ["GET"],
							"path": "^/api/v1/workflows/[^/]+$",
							"match_type": "regex",
							"action": "workflow-read"
						},
						{
							"name": "workflow-delete",
							"methods": ["DELETE"],
							"path": "^/api/v1/workflows/[^/]+$",
							"match_type": "regex",
							"action": "workflow-delete"
						}
					]
				}
			]
		}
	]`)
	eng, err := NewEngine(nil, nil, WithHTTPSchemas([]string{schemaPath}))
	require.NoError(t, err)

	groupNamePolicies := NewPolicyRegistry()
	require.NoError(t, groupNamePolicies.AddPolicy(&models.Policy{
		ID:   "workflow-group-name-http",
		Name: "Workflow Group Name HTTP",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "svc",
				Actions:    []string{"workflow"},
			},
		},
	}))

	allowed, policyID, err := eng.CheckHTTP(context.Background(), groupNamePolicies, "DELETE", "/api/v1/workflows/workflow-1")
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.Empty(t, policyID)

	routeActionPolicies := NewPolicyRegistry()
	require.NoError(t, routeActionPolicies.AddPolicy(&models.Policy{
		ID:   "workflow-delete-http",
		Name: "Workflow Delete HTTP",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "svc",
				Actions:    []string{"workflow-delete"},
			},
		},
	}))

	allowed, policyID, err = eng.CheckHTTP(context.Background(), routeActionPolicies, "DELETE", "/api/v1/workflows/workflow-1")
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, "workflow-delete-http", policyID)
}

func TestEngineCheckHTTP_AllowsIndividualRouteActionInGroupedSchema(t *testing.T) {
	schemaPath := writeHTTPSchemaTestFile(t, `[
		{
			"name": "svc",
			"groups": [
				{
					"name": "System Group",
					"routes": [
						{
							"name": "status-read",
							"methods": ["GET"],
							"path": "/api/v1/status",
							"match_type": "exact",
							"action": "status-read"
						}
					]
				}
			]
		}
	]`)
	eng, err := NewEngine(nil, nil, WithHTTPSchemas([]string{schemaPath}))
	require.NoError(t, err)

	policies := NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{
		ID:   "status-http",
		Name: "Status HTTP",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "svc",
				Actions:    []string{"status-read"},
			},
		},
	}))

	allowed, policyID, err := eng.CheckHTTP(context.Background(), policies, "GET", "/api/v1/status")
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, "status-http", policyID)
}

func TestEngineCheckHTTPRequest_SubjectConstraints(t *testing.T) {
	schemaPath := writeHTTPSchemaTestFile(t, `[
		{
			"name": "svc",
			"routes": [
				{
					"name": "path-read",
					"methods": ["GET"],
					"path": "^/api/v1/devices/([^/]+)/jobs$",
					"match_type": "regex",
					"action": "path-read",
					"constraints": [
						{
							"request": {"source": "path_regex_group", "index": 1},
							"equals_subject_attribute": "device_id"
						}
					]
				},
				{
					"name": "query-read",
					"methods": ["GET"],
					"path": "/api/v1/query",
					"match_type": "exact",
					"action": "query-read",
					"constraints": [
						{
							"request": {"source": "query", "name": "device_id"},
							"equals_subject_attribute": "device_id"
						}
					]
				},
				{
					"name": "header-read",
					"methods": ["GET"],
					"path": "/api/v1/header",
					"match_type": "exact",
					"action": "header-read",
					"constraints": [
						{
							"request": {"source": "header", "name": "x-device-id"},
							"equals_subject_attribute": "device_id"
						}
					]
				},
				{
					"name": "body-read",
					"methods": ["POST"],
					"path": "/api/v1/body",
					"match_type": "exact",
					"action": "body-read",
					"constraints": [
						{
							"request": {"source": "json_body", "path": "$.device.id"},
							"equals_subject_attribute": "device_id"
						}
					]
				}
			]
		}
	]`)
	eng, err := NewEngine(nil, nil, WithHTTPSchemas([]string{schemaPath}))
	require.NoError(t, err)

	policies := NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{
		ID:   "device-http",
		Name: "Device HTTP",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "svc",
				Actions:    []string{"path-read", "query-read", "header-read", "body-read"},
			},
		},
	}))

	subject := SubjectPolicySet{
		Subject: ResolvedSubject{
			PrincipalID: "principal-device-1",
			Attributes:  map[string]string{"device_id": "device-1"},
		},
		Policies: policies,
	}
	subjectMissingAttribute := SubjectPolicySet{
		Subject: ResolvedSubject{
			PrincipalID: "principal-missing-attribute",
			Attributes:  map[string]string{},
		},
		Policies: policies,
	}

	tests := []struct {
		name string
		req  HTTPCheckRequest
		want bool
	}{
		{
			name: "path group allows matching subject attribute",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/v1/devices/device-1/jobs",
				Subjects: []SubjectPolicySet{subject},
			},
			want: true,
		},
		{
			name: "path group denies different subject attribute",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/v1/devices/device-2/jobs",
				Subjects: []SubjectPolicySet{subject},
			},
			want: false,
		},
		{
			name: "path group denies missing subject attribute",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/v1/devices/device-1/jobs",
				Subjects: []SubjectPolicySet{subjectMissingAttribute},
			},
			want: false,
		},
		{
			name: "query allows matching subject attribute",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/v1/query",
				RawQuery: "device_id=device-1",
				Subjects: []SubjectPolicySet{subject},
			},
			want: true,
		},
		{
			name: "header allows matching subject attribute",
			req: HTTPCheckRequest{
				Method:   "GET",
				Path:     "/api/v1/header",
				Headers:  map[string]string{"x-device-id": "device-1"},
				Subjects: []SubjectPolicySet{subject},
			},
			want: true,
		},
		{
			name: "json body allows matching subject attribute",
			req: HTTPCheckRequest{
				Method:   "POST",
				Path:     "/api/v1/body",
				Body:     []byte(`{"device":{"id":"device-1"}}`),
				Subjects: []SubjectPolicySet{subject},
			},
			want: true,
		},
		{
			name: "malformed json body denies",
			req: HTTPCheckRequest{
				Method:   "POST",
				Path:     "/api/v1/body",
				Body:     []byte(`{`),
				Subjects: []SubjectPolicySet{subject},
			},
			want: false,
		},
		{
			name: "too large json body denies",
			req: HTTPCheckRequest{
				Method:       "POST",
				Path:         "/api/v1/body",
				BodyTooLarge: true,
				Subjects:     []SubjectPolicySet{subject},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eng.CheckHTTPRequest(context.Background(), tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result.Allowed)
			if tt.want {
				assert.Equal(t, "device-http", result.MatchedPolicyID)
				assert.Equal(t, "principal-device-1", result.MatchedPrincipalID)
			}
		})
	}
}

func TestEngineCheckHTTPRequest_DoesNotMixPolicyAndConstraintAcrossSubjects(t *testing.T) {
	schemaPath := writeHTTPSchemaTestFile(t, `[
		{
			"name": "svc",
			"routes": [
				{
					"name": "path-read",
					"methods": ["GET"],
					"path": "^/api/v1/devices/([^/]+)/jobs$",
					"match_type": "regex",
					"action": "path-read",
					"constraints": [
						{
							"request": {"source": "path_regex_group", "index": 1},
							"equals_subject_attribute": "device_id"
						}
					]
				}
			]
		}
	]`)
	eng, err := NewEngine(nil, nil, WithHTTPSchemas([]string{schemaPath}))
	require.NoError(t, err)

	grantingPolicies := NewPolicyRegistry()
	require.NoError(t, grantingPolicies.AddPolicy(&models.Policy{
		ID:   "granting-policy",
		Name: "Granting Policy",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "svc",
				Actions:    []string{"path-read"},
			},
		},
	}))
	emptyPolicies := NewPolicyRegistry()

	result, err := eng.CheckHTTPRequest(context.Background(), HTTPCheckRequest{
		Method: "GET",
		Path:   "/api/v1/devices/device-1/jobs",
		Subjects: []SubjectPolicySet{
			{
				Subject: ResolvedSubject{
					PrincipalID: "policy-subject",
					Attributes:  map[string]string{"device_id": "device-2"},
				},
				Policies: grantingPolicies,
			},
			{
				Subject: ResolvedSubject{
					PrincipalID: "identity-subject",
					Attributes:  map[string]string{"device_id": "device-1"},
				},
				Policies: emptyPolicies,
			},
		},
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Empty(t, result.MatchedPolicyID)
	assert.Empty(t, result.MatchedPrincipalID)
}

func TestHTTPSchemaRegistry_LoadFlatRoutes(t *testing.T) {
	registry := NewHTTPSchemaRegistry()
	schemaPath := writeHTTPSchemaTestFile(t, `[
		{
			"name": "svc",
			"routes": [
				{
					"name": "status-read",
					"methods": ["GET"],
					"path": "/api/v1/status",
					"match_type": "exact",
					"action": "status-read"
				}
			]
		}
	]`)

	require.NoError(t, registry.Load(schemaPath))
	schema, err := registry.Get("svc")
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"status-read"}, schema.AllActions)
	route := schema.MatchRoute("GET", "/api/v1/status")
	require.NotNil(t, route)
	assert.Equal(t, "status-read", route.Action)
}

func writeHTTPSchemaTestFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "http_schema.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}
