package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/service"
	"github.com/stretchr/testify/assert"
)

// failingPrincipalService answers every lookup with err.
type failingPrincipalService struct {
	service.PrincipalService
	err error
}

func (s failingPrincipalService) GetPrincipal(context.Context, string) (*models.Principal, error) {
	return nil, s.err
}

func (s failingPrincipalService) DeletePrincipal(context.Context, string) error { return s.err }

func (s failingPrincipalService) GrantPolicy(context.Context, string, string, string) error {
	return s.err
}

// Only a missing principal is a 404: a store failure must not look like "already gone" to callers.
func TestPrincipalController_NotFoundOnlyWhenMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	requests := map[string]func() *http.Request{
		"get": func() *http.Request { return httptest.NewRequest(http.MethodGet, "/principals/p-1", nil) },
		"update": func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "/principals/p-1", strings.NewReader(`{}`))
		},
		"delete": func() *http.Request { return httptest.NewRequest(http.MethodDelete, "/principals/p-1", nil) },
		"grant": func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/principals/p-1/policies", strings.NewReader(`{"policy_id":"policy-a"}`))
		},
	}
	for name, newRequest := range requests {
		for err, want := range map[error]int{
			fmt.Errorf("principal not found: p-1"):    http.StatusNotFound,
			errors.New("get principal: conn refused"): http.StatusInternalServerError,
		} {
			t.Run(fmt.Sprintf("%s/%d", name, want), func(t *testing.T) {
				ctrl := NewPrincipalController(failingPrincipalService{err: err})
				router := gin.New()
				router.GET("/principals/:id", ctrl.GetPrincipal)
				router.PUT("/principals/:id", ctrl.UpdatePrincipal)
				router.DELETE("/principals/:id", ctrl.DeletePrincipal)
				router.POST("/principals/:id/policies", ctrl.GrantPolicy)

				req := newRequest()
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				assert.Equal(t, want, rec.Code)
			})
		}
	}
}
