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

func TestCreatePolicy_SchemaMismatchIsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	schemas, err := authz.PKISchemas()
	require.NoError(t, err)

	// want is a fragment of the validation message, so a 400 from JSON binding does not pass.
	cases := map[string]struct{ entityType, toEntityType, via, want string }{
		"undeclared via":           {"issuance_profile", "ca_certificate", "parent", `\"parent\"`},
		"unloaded target":          {"issuance_profile", "no_such_entity", "profile_id", "no_such_entity"},
		"unloaded wildcard target": {"*", "no_such_entity", "profile_id", "no_such_entity"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			policyManager := service.NewPolicyManager(store.NewInMemoryPolicyStore(), service.WithPolicySchemas(schemas))
			ctrl := NewPolicyController(policyManager, nil)
			router := gin.New()
			router.POST("/policies", ctrl.CreatePolicy)

			body, err := json.Marshal(map[string]any{
				"id":   "bad-relation",
				"name": "Bad relation",
				"rules": []map[string]any{{
					"namespace": "pki", "schema_name": "ca", "entity_type": tc.entityType,
					"actions": []string{"read"},
					"relations": []map[string]any{{
						"to":  map[string]any{"schema_name": "ca", "entity_type": tc.toEntityType},
						"via": tc.via, "actions": []string{"read"},
					}},
				}},
			})
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.want)
		})
	}
}
