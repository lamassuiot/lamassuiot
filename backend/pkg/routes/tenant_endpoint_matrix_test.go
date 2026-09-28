package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

func TestTenantAdministrativeEndpointPermissionMatrix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authorizer := &endpointMatrixAuthorizer{}
	options := TenantRouteOptions{
		Memberships:      endpointMatrixMemberships{},
		IdentityProvider: endpointMatrixIdentityProvider,
		Authorization:    authorizer,
		Versioning: config.HttpServerVersioning{
			V1DefaultTenantID: "tenant-a",
			V1SunsetAt:        time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	registrars := map[string]func(*gin.RouterGroup){
		"ca":             func(root *gin.RouterGroup) { NewCAHTTPLayer(root, nil, options) },
		"kms":            func(root *gin.RouterGroup) { NewKMSHTTPLayer(root, nil, options) },
		"device-manager": func(root *gin.RouterGroup) { NewDeviceManagerHTTPLayer(root, nil, options) },
		"dms-manager": func(root *gin.RouterGroup) {
			NewDMSManagerHTTPLayer(logrus.New().WithField("test", "endpoint-matrix"), root, nil, options)
		},
		"va": func(root *gin.RouterGroup) {
			NewValidationRoutes(logrus.New().WithField("test", "endpoint-matrix"), root, nil, nil, options)
		},
		"alerts": func(root *gin.RouterGroup) { NewAlertsHTTPLayer(root, nil, options) },
	}

	for _, group := range tenantAdministrativeEndpointGroups {
		t.Run(group.service, func(t *testing.T) {
			router := gin.New()
			registrars[group.service](router.Group("/"))
			registered := make(map[string]struct{})
			for _, route := range router.Routes() {
				registered[route.Method+" "+route.Path] = struct{}{}
			}
			expected := make(map[string]string)
			for _, endpoint := range group.endpoints {
				for _, versionedPath := range []string{
					"/v1" + endpoint.path,
					"/api/v2/tenants/:tenantId" + endpoint.path,
				} {
					key := endpoint.method + " " + versionedPath
					if _, exists := expected[key]; exists {
						t.Fatalf("duplicate endpoint matrix entry: %s", key)
					}
					expected[key] = endpoint.permission
					if _, exists := registered[key]; !exists {
						t.Errorf("endpoint matrix route is not registered: %s", key)
					}
				}
			}
			for route := range registered {
				_, path, _ := strings.Cut(route, " ")
				if strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/api/v2/tenants/:tenantId/") {
					if _, exists := expected[route]; !exists {
						t.Errorf("tenant administrative route is missing from the endpoint matrix: %s", route)
					}
				}
			}

			for route, expectedPermission := range expected {
				t.Run(route, func(t *testing.T) {
					authorizer.requests = nil
					method, routePath, _ := strings.Cut(route, " ")
					routePath = strings.ReplaceAll(routePath, ":tenantId", "tenant-a")
					routePath = endpointMatrixConcretePath(routePath)
					request := httptest.NewRequest(method, routePath, nil)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, request)
					if response.Code != http.StatusForbidden {
						t.Fatalf("expected authorization gate to deny before handler, got status=%d body=%s", response.Code, response.Body.String())
					}
					if len(authorizer.requests) != 1 {
						t.Fatalf("expected one authorization check, got %d", len(authorizer.requests))
					}
					authorizedRequest := authorizer.requests[0]
					if authorizedRequest.Operation != expectedPermission {
						t.Errorf("expected permission %q, got %q", expectedPermission, authorizedRequest.Operation)
					}
					if authorizedRequest.TenantContext.TenantID != "tenant-a" || !authorizedRequest.TenantContext.Validated {
						t.Errorf("expected validated tenant-a context at authorization boundary, got %+v", authorizedRequest.TenantContext)
					}
					if authorizedRequest.Identity.Issuer != "matrix-issuer" || authorizedRequest.Identity.Subject != "matrix-actor" {
						t.Errorf("expected authenticated matrix identity, got %+v", authorizedRequest.Identity)
					}
				})
			}
		})
	}
}

type tenantAdministrativeEndpoint struct {
	method     string
	path       string
	permission string
}

type tenantEndpointGroup struct {
	service   string
	endpoints []tenantAdministrativeEndpoint
}

var tenantAdministrativeEndpointGroups = []tenantEndpointGroup{
	{service: "ca", endpoints: []tenantAdministrativeEndpoint{
		{http.MethodGet, "/cas", "ca.read"},
		{http.MethodPost, "/cas", "ca.write"},
		{http.MethodPost, "/cas/import", "ca.write"},
		{http.MethodGet, "/cas/:id", "ca.read"},
		{http.MethodGet, "/cas/cn/:cn", "ca.read"},
		{http.MethodPut, "/cas/:id/metadata", "ca.write"},
		{http.MethodPatch, "/cas/:id/metadata", "ca.write"},
		{http.MethodPost, "/cas/:id/status", "ca.write"},
		{http.MethodPost, "/cas/:id/profile", "ca.write"},
		{http.MethodPost, "/cas/:id/reissue", "ca.write"},
		{http.MethodGet, "/cas/:id/certificates", "certificate.read"},
		{http.MethodGet, "/cas/:id/certificates/status/:status", "certificate.read"},
		{http.MethodPost, "/cas/:id/certificates/sign", "certificate.issue"},
		{http.MethodPost, "/cas/:id/signature/sign", "ca.sign"},
		{http.MethodPost, "/cas/:id/signature/verify", "ca.sign"},
		{http.MethodGet, "/cas/:id/certificates/:sn", "certificate.read"},
		{http.MethodDelete, "/cas/:id", "ca.write"},
		{http.MethodGet, "/certificates", "certificate.read"},
		{http.MethodGet, "/certificates/status/:status", "certificate.read"},
		{http.MethodGet, "/certificates/expiration", "certificate.read"},
		{http.MethodGet, "/certificates/:sn", "certificate.read"},
		{http.MethodPut, "/certificates/:sn/status", "certificate.revoke"},
		{http.MethodPut, "/certificates/:sn/metadata", "certificate.write"},
		{http.MethodPatch, "/certificates/:sn/metadata", "certificate.write"},
		{http.MethodDelete, "/certificates/:sn", "certificate.write"},
		{http.MethodPost, "/certificates/import", "certificate.write"},
		{http.MethodPost, "/certificates", "certificate.issue"},
		{http.MethodGet, "/stats", "ca.read"},
		{http.MethodGet, "/stats/:id", "ca.read"},
		{http.MethodGet, "/profiles", "profile.read"},
		{http.MethodGet, "/profiles/:id", "profile.read"},
		{http.MethodPost, "/profiles", "profile.write"},
		{http.MethodPut, "/profiles/:id", "profile.write"},
		{http.MethodDelete, "/profiles/:id", "profile.write"},
	}},
	{service: "kms", endpoints: []tenantAdministrativeEndpoint{
		{http.MethodGet, "/stats", "kms.read"},
		{http.MethodGet, "/engines", "kms.read"},
		{http.MethodGet, "/keys", "key.read"},
		{http.MethodGet, "/keys/:id", "key.read"},
		{http.MethodPost, "/keys", "key.manage"},
		{http.MethodPost, "/keys/import", "key.import"},
		{http.MethodPut, "/keys/:id/alias", "key.manage"},
		{http.MethodPut, "/keys/:id/name", "key.manage"},
		{http.MethodPut, "/keys/:id/tags", "key.manage"},
		{http.MethodPut, "/keys/:id/metadata", "key.manage"},
		{http.MethodDelete, "/keys/:id", "key.manage"},
		{http.MethodPost, "/keys/:id/sign", "key.sign"},
		{http.MethodPost, "/keys/:id/verify", "key.verify"},
	}},
	{service: "device-manager", endpoints: []tenantAdministrativeEndpoint{
		{http.MethodGet, "/stats", "device.read"},
		{http.MethodGet, "/devices", "device.read"},
		{http.MethodPost, "/devices", "device.write"},
		{http.MethodGet, "/devices/:id", "device.read"},
		{http.MethodDelete, "/devices/:id", "device.write"},
		{http.MethodPut, "/devices/:id/idslot", "device.write"},
		{http.MethodPut, "/devices/:id/metadata", "device.write"},
		{http.MethodPatch, "/devices/:id/metadata", "device.write"},
		{http.MethodDelete, "/devices/:id/decommission", "device.decommission"},
		{http.MethodGet, "/devices/dms/:id", "device.read"},
		{http.MethodPost, "/device-groups", "group.write"},
		{http.MethodGet, "/device-groups", "group.read"},
		{http.MethodGet, "/device-groups/:id", "group.read"},
		{http.MethodPut, "/device-groups/:id", "group.write"},
		{http.MethodDelete, "/device-groups/:id", "group.write"},
		{http.MethodGet, "/device-groups/:id/devices", "group.read"},
		{http.MethodGet, "/device-groups/:id/stats", "group.read"},
	}},
	{service: "dms-manager", endpoints: []tenantAdministrativeEndpoint{
		{http.MethodGet, "/stats", "dms.read"},
		{http.MethodGet, "/dms", "dms.read"},
		{http.MethodPost, "/dms", "dms.write"},
		{http.MethodGet, "/dms/:id", "dms.read"},
		{http.MethodPut, "/dms/:id", "dms.write"},
		{http.MethodPut, "/dms/:id/metadata", "dms.write"},
		{http.MethodPatch, "/dms/:id/metadata", "dms.write"},
		{http.MethodDelete, "/dms/:id", "dms.write"},
		{http.MethodPost, "/dms/bind-identity", "identity.bind"},
	}},
	{service: "va", endpoints: []tenantAdministrativeEndpoint{
		{http.MethodGet, "/roles/:ca-ski", "va.read"},
		{http.MethodPut, "/roles/:ca-ski", "role.manage"},
	}},
	{service: "alerts", endpoints: []tenantAdministrativeEndpoint{
		{http.MethodGet, "/events/latest", "alert.read"},
		{http.MethodGet, "/user/:userId/subscriptions", "alert.read"},
		{http.MethodPost, "/user/:userId/subscribe", "subscription.manage"},
		{http.MethodPost, "/user/:userId/unsubscribe/:subId", "subscription.manage"},
	}},
}

type endpointMatrixAuthorizer struct {
	requests []tenantcontext.AuthorizationRequest
}

func (authorizer *endpointMatrixAuthorizer) Authorize(_ context.Context, request tenantcontext.AuthorizationRequest) error {
	authorizer.requests = append(authorizer.requests, request)
	return errors.New("endpoint matrix denies before controller execution")
}

type endpointMatrixMemberships struct{}

func (endpointMatrixMemberships) FindActiveMembership(_ context.Context, issuer, subject, tenantID string) (*models.Membership, *models.Tenant, error) {
	if tenantID != "tenant-a" || issuer != "matrix-issuer" || subject != "matrix-actor" {
		return nil, nil, storage.ErrActiveMembershipNotFound
	}
	return &models.Membership{
		ID: "matrix-membership", OrganizationID: "matrix-org", TenantID: tenantID,
		IdentityIssuer: issuer, IdentitySubject: subject, Role: models.RoleOperator, Status: models.MembershipActive,
	}, &models.Tenant{
		ID: tenantID, OrganizationID: "matrix-org", Status: models.TenantActive, IsolationMode: models.IsolationPooled,
	}, nil
}

var _ storage.ControlPlaneMembershipRepo = endpointMatrixMemberships{}

func endpointMatrixIdentityProvider(context.Context) (tenantcontext.AuthenticatedIdentity, error) {
	return tenantcontext.AuthenticatedIdentity{
		Issuer: "matrix-issuer", Subject: "matrix-actor", ActorType: "HUMAN",
	}, nil
}

func endpointMatrixConcretePath(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		if strings.HasPrefix(segment, ":") {
			segments[index] = fmt.Sprintf("parameter-%d", index)
		}
	}
	return strings.Join(segments, "/")
}
