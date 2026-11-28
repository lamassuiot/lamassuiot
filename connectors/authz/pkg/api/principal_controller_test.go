package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/service"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/store"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingPrincipalService captures CreatePrincipal calls and returns listErr
// from ListPrincipals. The other PrincipalService methods are not used by
// these tests.
type recordingPrincipalService struct {
	service.PrincipalService
	created []*models.Principal
	listErr error
}

func (s *recordingPrincipalService) ListPrincipals(context.Context, *resources.QueryParameters) ([]*models.Principal, string, error) {
	return nil, "", s.listErr
}

func (s *recordingPrincipalService) CreatePrincipal(_ context.Context, p *models.Principal) error {
	s.created = append(s.created, p)
	return nil
}

func postPrincipal(t *testing.T, svc service.PrincipalService, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/principals", NewPrincipalController(svc).CreatePrincipal)

	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestCreatePrincipal_RequiresType(t *testing.T) {
	svc := &recordingPrincipalService{}

	for name, body := range map[string]map[string]any{
		"missing": {"name": "John Doe", "auth_config": map[string]any{}},
		"empty":   {"name": "John Doe", "type": "", "auth_config": map[string]any{}},
	} {
		t.Run(name, func(t *testing.T) {
			rec := postPrincipal(t, svc, body)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
	assert.Empty(t, svc.created, "a principal without type must not reach the service")
}

func TestCreatePrincipal_WithoutAuthConfig(t *testing.T) {
	svc := &recordingPrincipalService{}

	rec := postPrincipal(t, svc, map[string]any{"name": "John Doe", "type": "oidc"})

	assert.Equal(t, http.StatusCreated, rec.Code)
	require.Len(t, svc.created, 1)
	assert.Equal(t, "oidc", svc.created[0].Type)
	assert.Empty(t, svc.created[0].AuthConfig)
}

func TestListPrincipals_InvalidQueryIsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		err  error
		want int
	}{
		{fmt.Errorf("list principals: %w", fmt.Errorf("%w: sorting by a JSONPath expression is not supported", store.ErrInvalidListQuery)), http.StatusBadRequest},
		{errors.New("connection refused"), http.StatusInternalServerError},
	} {
		router := gin.New()
		router.GET("/principals", NewPrincipalController(&recordingPrincipalService{listErr: tc.err}).ListPrincipals)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/principals", nil))
		assert.Equal(t, tc.want, rec.Code, tc.err.Error())
	}
}
