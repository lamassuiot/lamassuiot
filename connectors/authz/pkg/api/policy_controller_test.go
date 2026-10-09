package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/authz/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePolicy_RejectsSystemManagedID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	policyManager := service.NewPolicyManager(store.NewInMemoryPolicyStore())
	ctrl := NewPolicyController(policyManager, nil)

	router := gin.New()
	router.POST("/policies", ctrl.CreatePolicy)

	body, err := json.Marshal(map[string]interface{}{
		"id":   "lamassu.custom",
		"name": "Custom Policy",
		"rules": []map[string]interface{}{
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
