package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamassuiot/authz/pkg/models"
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

	allowed, policyID, err := eng.CheckHTTP(context.Background(), sbiPolicies, "PUT", "/api/wfx/sbi/v1/jobs/job-1/status")
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, "sbi-job-status-update", policyID)

	allowed, policyID, err = eng.CheckHTTP(context.Background(), sbiPolicies, "PUT", "/api/wfx/nbi/v1/jobs/job-1/status")
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
