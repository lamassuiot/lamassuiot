package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authz "github.com/lamassuiot/lamassuiot/v4/connectors/authz"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/service"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePolicy_RejectsSystemManagedID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	policyManager := service.NewPolicyManager(store.NewInMemoryPolicyStore())
	ctrl := NewPolicyController(policyManager, nil)

	router := gin.New()
	router.POST("/policies", ctrl.CreatePolicy)

	body, err := json.Marshal(map[string]any{
		"id":   "lamassu.custom",
		"name": "Custom Policy",
		"rules": []map[string]any{
			{
				"namespace":  "iot",
				"schemaName": "public",
				"entityType": "organization",
				"actions":    []string{"read"},
			},
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	_, err = policyManager.GetPolicy(context.Background(), "lamassu.custom")
	assert.Error(t, err, "system-managed policy must not be stored")
}

// Both write paths map a schema mismatch to 400: PUT goes through its own errors.Is branch.
func TestPolicyWrite_SchemaMismatchIsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	schemas, err := authz.PKISchemas()
	require.NoError(t, err)

	// want is a fragment of the validation message, so a 400 from JSON binding does not pass.
	cases := map[string]struct{ entityType, toEntityType, via, want string }{
		"undeclared via":           {"issuance_profile", "ca_certificate", "parent", `\"parent\"`},
		"unloaded target":          {"issuance_profile", "no_such_entity", "profile_id", "no_such_entity"},
		"unloaded wildcard target": {"*", "no_such_entity", "profile_id", "no_such_entity"},
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for name, tc := range cases {
			t.Run(method+" "+name, func(t *testing.T) {
				policyManager := service.NewPolicyManager(store.NewInMemoryPolicyStore(), service.WithPolicySchemas(schemas))
				ctrl := NewPolicyController(policyManager, nil)
				router := gin.New()
				router.POST("/policies", ctrl.CreatePolicy)
				router.PUT("/policies/:id", ctrl.UpdatePolicy)

				send := func(method, path string, payload map[string]any) *httptest.ResponseRecorder {
					body, err := json.Marshal(payload)
					require.NoError(t, err)
					req := httptest.NewRequest(method, path, bytes.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					return rec
				}
				rule := func(relations []map[string]any) []map[string]any {
					return []map[string]any{{
						"namespace": "pki", "schema_name": "ca", "entity_type": tc.entityType,
						"actions": []string{"read"}, "relations": relations,
					}}
				}
				badRules := rule([]map[string]any{{
					"to":  map[string]any{"schema_name": "ca", "entity_type": tc.toEntityType},
					"via": tc.via, "actions": []string{"read"},
				}})

				var rec *httptest.ResponseRecorder
				if method == http.MethodPost {
					rec = send(http.MethodPost, "/policies", map[string]any{"id": "bad-relation", "name": "Bad relation", "rules": badRules})
				} else {
					seed := send(http.MethodPost, "/policies", map[string]any{"id": "bad-relation", "name": "Bad relation", "rules": rule(nil)})
					require.Equal(t, http.StatusCreated, seed.Code, seed.Body.String())
					rec = send(http.MethodPut, "/policies/bad-relation", map[string]any{"name": "Bad relation", "rules": badRules})
				}

				assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
				assert.Contains(t, rec.Body.String(), tc.want)
			})
		}
	}
}
