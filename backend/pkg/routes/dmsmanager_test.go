package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	authzcore "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/core"
	middleware "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var grantDeclaration = middleware.Declaration{Namespace: "authz", SchemaName: "public", EntityType: "principal_policy", Action: "grant"}

// grantEngine lets the caller create and update RAs, and grant policies only when grant is set.
type grantEngine struct {
	authzcore.AuthzEngine
	grant bool
	asked []middleware.Declaration
}

func (e *grantEngine) MatchAndAuthorize(_ context.Context, _, _, namespace, schema, action, entity string, _ map[string]string) (bool, []string, error) {
	e.asked = append(e.asked, middleware.Declaration{Namespace: namespace, SchemaName: schema, EntityType: entity, Action: action})
	return namespace != "authz" || e.grant, []string{"user"}, nil
}

// saves answers a create and an update: it asks the check of the caller, as the service does when an RA asks for more, and fails with err.
type saves struct {
	services.DMSManagerService
	err     error
	allowed []bool
}

func (s *saves) answer(ctx context.Context, id string) (*models.DMS, error) {
	check := services.PolicyGrantCheckFrom(ctx)
	allowed := false
	if check != nil {
		allowed, _ = check(ctx)
	}
	s.allowed = append(s.allowed, allowed)
	return &models.DMS{ID: id}, s.err
}

func (s *saves) CreateDMS(ctx context.Context, in services.CreateDMSInput) (*models.DMS, error) {
	return s.answer(ctx, in.ID)
}

func (s *saves) UpdateDMS(ctx context.Context, in services.UpdateDMSInput) (*models.DMS, error) {
	return s.answer(ctx, in.ID)
}

// postAndPut sends a create and an update of an RA, as an authenticated user or as an internal service.
func postAndPut(svc services.DMSManagerService, engine authzcore.AuthzEngine, internal bool) []*httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("lamassu.io/ctx/auth-type", "jwt")
		c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
		c.Next()
	})
	registerDMSManagerRoutes(logrus.NewEntry(logrus.New()), router.Group("/api/dmsmanager"), svc, engine)

	var responses []*httptest.ResponseRecorder
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/dmsmanager/v1/dms", strings.NewReader(`{"id":"ra-1","name":"RA 1","settings":{}}`)),
		httptest.NewRequest(http.MethodPut, "/api/dmsmanager/v1/dms/ra-1", strings.NewReader(`{"name":"RA 1","settings":{}}`)),
	} {
		if internal {
			req.Header.Set("X-Principal-ID", "admin-mode")
		}
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		responses = append(responses, res)
	}
	return responses
}

// Only the HTTP layer knows who calls, so it hands the service the check of that caller's grant permission.
func TestDMSWritesCarryTheCallersPolicyGrantCheck(t *testing.T) {
	cases := []struct {
		name         string
		grant, admin bool
	}{
		{name: "caller allowed to grant policies", grant: true},
		{name: "caller not allowed to grant policies"},
		{name: "internal service", admin: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, svc := &grantEngine{grant: tc.grant}, &saves{}

			for _, res := range postAndPut(svc, engine, tc.admin) {
				assert.Less(t, res.Code, 300)
			}

			want := tc.grant || tc.admin
			assert.Equal(t, []bool{want, want}, svc.allowed)
			assert.Equal(t, !tc.admin, slices.Contains(engine.asked, grantDeclaration), "an internal service is trusted, anyone else is asked")
		})
	}
}

func TestDMSSavesMapTheErrorsOfTheServiceToStatusCodes(t *testing.T) {
	cases := map[int]error{
		http.StatusForbidden:           errs.ErrDMSAuthzPolicyGrantForbidden,
		http.StatusBadRequest:          fmt.Errorf("%w: authz policy p does not exist", errs.ErrValidateBadRequest),
		http.StatusInternalServerError: errors.New("db down"),
	}
	for status, err := range cases {
		t.Run(http.StatusText(status), func(t *testing.T) {
			for _, res := range postAndPut(&saves{err: err}, &grantEngine{grant: true}, false) {
				assert.Equal(t, status, res.Code)
				assert.Contains(t, res.Body.String(), err.Error(), "the body carries the reason")
			}
		})
	}
}

// The grant check is part of the route contract, and only the saves of the settings ask for it.
func TestDMSWritesDeclareTheirPolicyGrantCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	contract := registerDMSManagerRoutes(logrus.NewEntry(logrus.New()), gin.New().Group("/api/dmsmanager"), nil, &grantEngine{})

	declared := map[string][]middleware.Declaration{}
	for _, route := range contract.Declarations() {
		if len(route.ServiceChecks) > 0 {
			declared[route.Method+" "+route.Path] = route.ServiceChecks
		}
	}

	only := []middleware.Declaration{grantDeclaration}
	assert.Equal(t, map[string][]middleware.Declaration{"POST /api/dmsmanager/v1/dms": only, "PUT /api/dmsmanager/v1/dms/:id": only}, declared)
}
