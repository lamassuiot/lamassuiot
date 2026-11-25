package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// grantEngine lets the caller create and update RAs, and grant policies only when grant is set.
type grantEngine struct {
	authzcore.AuthzEngine
	grant bool
	asked []middleware.Declaration
}

func (e *grantEngine) MatchAndAuthorize(_ context.Context, _, _, namespace, schema, action, entity string, _ map[string]string) (bool, []string, error) {
	e.asked = append(e.asked, middleware.Declaration{Namespace: namespace, SchemaName: schema, EntityType: entity, Action: action})
	if namespace == "authz" {
		return e.grant, nil, nil
	}
	return true, []string{"user"}, nil
}

// grantCheckRecorder runs the policy grant check it gets, as the service does when an RA asks for more.
type grantCheckRecorder struct {
	services.DMSManagerService
	allowed []bool
}

func (s *grantCheckRecorder) run(ctx context.Context) {
	allowed := false
	if check := services.PolicyGrantCheckFrom(ctx); check != nil {
		allowed, _ = check(ctx)
	}
	s.allowed = append(s.allowed, allowed)
}

func (s *grantCheckRecorder) CreateDMS(ctx context.Context, in services.CreateDMSInput) (*models.DMS, error) {
	s.run(ctx)
	return &models.DMS{ID: in.ID}, nil
}

func (s *grantCheckRecorder) UpdateDMS(ctx context.Context, in services.UpdateDMSInput) (*models.DMS, error) {
	s.run(ctx)
	return &models.DMS{ID: in.ID}, nil
}

// Only the HTTP layer knows who calls, so it hands the service the check of that caller's grant permission.
func TestDMSWritesCarryTheCallersPolicyGrantCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name         string
		grant, admin bool
		want         bool
	}{
		{name: "caller allowed to grant policies", grant: true, want: true},
		{name: "caller not allowed to grant policies"},
		{name: "internal service", admin: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("lamassu.io/ctx/auth-type", "jwt")
				c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
				c.Next()
			})
			engine, svc := &grantEngine{grant: tc.grant}, &grantCheckRecorder{}
			registerDMSManagerRoutes(logrus.NewEntry(logrus.New()), router.Group("/api/dmsmanager"), svc, engine)

			for _, req := range []*http.Request{
				httptest.NewRequest(http.MethodPost, "/api/dmsmanager/v1/dms", strings.NewReader(`{"id":"ra-1","name":"RA 1","settings":{}}`)),
				httptest.NewRequest(http.MethodPut, "/api/dmsmanager/v1/dms/ra-1", strings.NewReader(`{"name":"RA 1","settings":{}}`)),
			} {
				if tc.admin {
					req.Header.Set("X-Principal-ID", "admin-mode")
				}
				res := httptest.NewRecorder()
				router.ServeHTTP(res, req)
				assert.Less(t, res.Code, 300, req.Method)
			}

			assert.Equal(t, []bool{tc.want, tc.want}, svc.allowed)
			if !tc.admin {
				assert.Contains(t, engine.asked, middleware.Declaration{Namespace: "authz", SchemaName: "public", EntityType: "principal_policy", Action: "grant"})
			}
		})
	}
}

// failingSaves answers a save with the given error, as the service does.
type failingSaves struct {
	services.DMSManagerService
	err error
}

func (s failingSaves) CreateDMS(context.Context, services.CreateDMSInput) (*models.DMS, error) {
	return nil, s.err
}

func (s failingSaves) UpdateDMS(context.Context, services.UpdateDMSInput) (*models.DMS, error) {
	return nil, s.err
}

func TestDMSSavesMapTheErrorsOfTheServiceToStatusCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{name: "the caller may not grant", err: errs.ErrDMSAuthzPolicyGrantForbidden, status: http.StatusForbidden},
		{name: "a bad request with details", err: fmt.Errorf("%w: authz policy p does not exist", errs.ErrValidateBadRequest), status: http.StatusBadRequest},
		{name: "anything else", err: errors.New("db down"), status: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("lamassu.io/ctx/auth-type", "jwt")
				c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
				c.Next()
			})
			registerDMSManagerRoutes(logrus.NewEntry(logrus.New()), router.Group("/api/dmsmanager"), failingSaves{err: tc.err}, &grantEngine{grant: true})

			for _, req := range []*http.Request{
				httptest.NewRequest(http.MethodPost, "/api/dmsmanager/v1/dms", strings.NewReader(`{"id":"ra-1","name":"RA 1","settings":{}}`)),
				httptest.NewRequest(http.MethodPut, "/api/dmsmanager/v1/dms/ra-1", strings.NewReader(`{"name":"RA 1","settings":{}}`)),
			} {
				res := httptest.NewRecorder()
				router.ServeHTTP(res, req)

				assert.Equal(t, tc.status, res.Code, req.Method)
				assert.Contains(t, res.Body.String(), tc.err.Error(), "the body carries the reason")
			}
		})
	}
}

// The grant check is part of the route contract: the spec must list it, and a route that loses it is caught.
func TestDMSWritesDeclareTheirPolicyGrantCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	contract := registerDMSManagerRoutes(logrus.NewEntry(logrus.New()), router.Group("/api/dmsmanager"), nil, &grantEngine{})
	grant := middleware.Declaration{Namespace: "authz", SchemaName: "public", EntityType: "principal_policy", Action: "grant"}

	with := map[string]bool{}
	for _, route := range contract.Declarations() {
		with[route.Method+" "+route.Path] = len(route.ServiceChecks) > 0
		if len(route.ServiceChecks) > 0 {
			assert.Equal(t, []middleware.Declaration{grant}, route.ServiceChecks, route.Path)
		}
	}
	assert.Equal(t, map[string]bool{"POST /api/dmsmanager/v1/dms": true, "PUT /api/dmsmanager/v1/dms/:id": true}, onlyTrue(with), "only the saves of the settings ask for it")
}

func onlyTrue(m map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range m {
		if v {
			out[k] = v
		}
	}
	return out
}
