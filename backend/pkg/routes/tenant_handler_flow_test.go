package routes

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

const (
	handlerFlowTenantA = "tenant-a"
	handlerFlowTenantB = "tenant-b"
	handlerFlowIssuer  = "handler-flow-issuer"
	handlerFlowSubject = "handler-flow-actor"
)

type handlerFlowMemberships struct {
	role models.TenantRole
}

func (repo handlerFlowMemberships) FindActiveMembership(_ context.Context, issuer, subject, tenantID string) (*models.Membership, *models.Tenant, error) {
	if issuer != handlerFlowIssuer || subject != handlerFlowSubject || tenantID != handlerFlowTenantA {
		return nil, nil, storage.ErrActiveMembershipNotFound
	}
	return &models.Membership{
		ID: "membership-a", OrganizationID: "organization-a", TenantID: handlerFlowTenantA,
		IdentityIssuer: issuer, IdentitySubject: subject, Role: repo.role, Status: models.MembershipActive,
	}, &models.Tenant{
		ID: handlerFlowTenantA, OrganizationID: "organization-a", Status: models.TenantActive,
		IsolationMode: models.IsolationPooled,
	}, nil
}

type handlerFlowAlertsService struct {
	calls     int
	tenantIDs []string
	tracker   *handlerFlowServiceTracker
}

func (service *handlerFlowAlertsService) HandleEvent(context.Context, *services.HandleEventInput) error {
	return nil
}

func (service *handlerFlowAlertsService) GetUserSubscriptions(ctx context.Context, _ *services.GetUserSubscriptionsInput) ([]*models.Subscription, error) {
	if err := service.recordTenant(ctx); err != nil {
		return nil, err
	}
	return []*models.Subscription{}, nil
}

func (service *handlerFlowAlertsService) Subscribe(ctx context.Context, _ *services.SubscribeInput) ([]*models.Subscription, error) {
	if err := service.recordTenant(ctx); err != nil {
		return nil, err
	}
	return []*models.Subscription{}, nil
}

func (service *handlerFlowAlertsService) Unsubscribe(ctx context.Context, _ *services.UnsubscribeInput) ([]*models.Subscription, error) {
	if err := service.recordTenant(ctx); err != nil {
		return nil, err
	}
	return []*models.Subscription{}, nil
}

func (service *handlerFlowAlertsService) GetLatestEventsPerEventType(ctx context.Context, _ *services.GetLatestEventsPerEventTypeInput) ([]*models.AlertLatestEvent, error) {
	if err := service.recordTenant(ctx); err != nil {
		return nil, err
	}
	return []*models.AlertLatestEvent{}, nil
}

func (service *handlerFlowAlertsService) recordTenant(ctx context.Context) error {
	tenant, err := core.RequireTenantContext(ctx)
	if err != nil || !tenant.Validated {
		return errors.New("validated tenant context did not reach Alerts service")
	}
	service.calls++
	service.tenantIDs = append(service.tenantIDs, tenant.TenantID)
	if service.tracker != nil {
		service.tracker.calls++
		service.tracker.tenantIDs = append(service.tracker.tenantIDs, tenant.TenantID)
	}
	return nil
}

func TestTenantHandlerFlowsReachServicesWithValidatedContextAndDenyTenantB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name      string
		path      string
		operation string
		role      models.TenantRole
		actorType string
		scopes    []string
		register  func(*gin.RouterGroup, *routesTenantOptions)
		assertA   func(*testing.T)
		assertB   func(*testing.T)
	}{
		{
			name: "CA get",
			path: "/cas/ca-a", operation: "ca.read", role: models.RoleViewer, actorType: "HUMAN",
			register: func(root *gin.RouterGroup, options *routesTenantOptions) {
				service := new(svcmock.MockCAService)
				service.On("GetCAByID", validatedHandlerFlowContext(), mock.Anything).Return(&models.CACertificate{ID: "ca-a"}, nil).Once()
				NewCAHTTPLayer(root, service, options.routes)
				options.assertA = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetCAByID", 1) }
				options.assertB = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetCAByID", 1) }
			},
		},
		{
			name: "KMS get key",
			path: "/keys/key-a", operation: "key.read", role: models.RolePKIAdmin, actorType: "SERVICE", scopes: []string{"key.read"},
			register: func(root *gin.RouterGroup, options *routesTenantOptions) {
				service := new(svcmock.MockKMSService)
				service.On("GetKey", validatedHandlerFlowContext(), mock.Anything).Return(&models.Key{KeyID: "key-a", TenantID: handlerFlowTenantA}, nil).Once()
				NewKMSHTTPLayer(root, service, options.routes)
				options.assertA = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetKey", 1) }
				options.assertB = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetKey", 1) }
			},
		},
		{
			name: "Device Manager get device",
			path: "/devices/device-a", operation: "device.read", role: models.RoleViewer, actorType: "HUMAN",
			register: func(root *gin.RouterGroup, options *routesTenantOptions) {
				service := new(svcmock.MockDeviceManagerService)
				service.On("GetDeviceByID", validatedHandlerFlowContext(), mock.Anything).Return(&models.Device{ID: "device-a", TenantID: handlerFlowTenantA}, nil).Once()
				NewDeviceManagerHTTPLayer(root, service, options.routes)
				options.assertA = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetDeviceByID", 1) }
				options.assertB = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetDeviceByID", 1) }
			},
		},
		{
			name: "DMS get",
			path: "/dms/dms-a", operation: "dms.read", role: models.RoleViewer, actorType: "HUMAN",
			register: func(root *gin.RouterGroup, options *routesTenantOptions) {
				service := new(svcmock.MockDMSManagerService)
				service.On("GetDMSByID", validatedHandlerFlowContext(), mock.Anything).Return(&models.DMS{ID: "dms-a", TenantID: handlerFlowTenantA}, nil).Once()
				NewDMSManagerHTTPLayer(logrus.NewEntry(logrus.New()), root, service, options.routes)
				options.assertA = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetDMSByID", 1) }
				options.assertB = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetDMSByID", 1) }
			},
		},
		{
			name: "VA get role",
			path: "/roles/ca-ski-a", operation: "va.read", role: models.RoleViewer, actorType: "HUMAN",
			register: func(root *gin.RouterGroup, options *routesTenantOptions) {
				service := new(svcmock.MockVAService)
				service.On("GetVARole", validatedHandlerFlowContext(), mock.Anything).Return(&models.VARole{CASubjectKeyID: "ca-ski-a", TenantID: handlerFlowTenantA}, nil).Once()
				NewValidationRoutes(logrus.NewEntry(logrus.New()), root, nil, service, options.routes)
				options.assertA = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetVARole", 1) }
				options.assertB = func(t *testing.T) { service.AssertNumberOfCalls(t, "GetVARole", 1) }
			},
		},
		{
			name: "Alerts latest events",
			path: "/events/latest", operation: "alert.read", role: models.RoleViewer, actorType: "HUMAN",
			register: func(root *gin.RouterGroup, options *routesTenantOptions) {
				service := &handlerFlowAlertsService{}
				NewAlertsHTTPLayer(root, service, options.routes)
				options.assertA = func(t *testing.T) {
					if service.calls != 1 || len(service.tenantIDs) != 1 || service.tenantIDs[0] != handlerFlowTenantA {
						t.Fatalf("expected one service call with tenant A, calls=%d tenants=%v", service.calls, service.tenantIDs)
					}
				}
				options.assertB = func(t *testing.T) { options.assertA(t) }
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := routesTenantOptions{routes: TenantRouteOptions{
				Memberships: handlerFlowMemberships{role: test.role},
				IdentityProvider: func(context.Context) (tenantcontext.AuthenticatedIdentity, error) {
					return tenantcontext.AuthenticatedIdentity{
						Issuer: handlerFlowIssuer, Subject: handlerFlowSubject,
						ActorType: test.actorType, Permissions: test.scopes,
					}, nil
				},
				Authorization: tenantcontext.NewPermissionAuthorizationEngine(),
			}}
			router := gin.New()
			test.register(router.Group("/"), &options)

			for _, tenantID := range []string{handlerFlowTenantA, handlerFlowTenantB} {
				path := "/api/v2/tenants/" + tenantID + test.path
				response := httptest.NewRecorder()
				router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
				wantStatus := http.StatusOK
				if tenantID == handlerFlowTenantB {
					wantStatus = http.StatusForbidden
				}
				if response.Code != wantStatus {
					t.Errorf("tenant %s: expected status %d, got %d body=%s", tenantID, wantStatus, response.Code, response.Body.String())
				}
			}
			options.assertA(t)
			options.assertB(t)
		})
	}
}

func TestEveryAdministrativeHandlerReachesServiceForAAndDeniesB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	importedPrivateKey, err := os.ReadFile(filepath.Join("..", "..", "..", "core", "pkg", "helpers", "testdata", "pkcs1pk.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keyImportBody := `{"private_key":"` + base64.StdEncoding.EncodeToString(importedPrivateKey) + `"}`
	options := TenantRouteOptions{
		Memberships: handlerFlowMemberships{role: models.RolePKIAdmin},
		IdentityProvider: func(context.Context) (tenantcontext.AuthenticatedIdentity, error) {
			return tenantcontext.AuthenticatedIdentity{
				Issuer: handlerFlowIssuer, Subject: handlerFlowSubject,
				ActorType: "HUMAN",
			}, nil
		},
		Authorization: tenantcontext.AuthorizationEngineFunc(func(_ context.Context, request tenantcontext.AuthorizationRequest) error {
			if !request.TenantContext.Validated || request.TenantContext.TenantID != handlerFlowTenantA {
				return errors.New("only a validated tenant A context is authorized")
			}
			return nil
		}),
	}

	registrars := map[string]func(*gin.RouterGroup, *handlerFlowServiceTracker){
		"ca": func(root *gin.RouterGroup, tracker *handlerFlowServiceTracker) {
			service := new(svcmock.MockCAService)
			registerHandlerFlowMockMethods(&service.Mock, reflect.TypeOf((*services.CAService)(nil)).Elem(), tracker)
			NewCAHTTPLayer(root, service, options)
		},
		"kms": func(root *gin.RouterGroup, tracker *handlerFlowServiceTracker) {
			service := new(svcmock.MockKMSService)
			registerHandlerFlowMockMethods(&service.Mock, reflect.TypeOf((*services.KMSService)(nil)).Elem(), tracker)
			NewKMSHTTPLayer(root, service, options)
		},
		"device-manager": func(root *gin.RouterGroup, tracker *handlerFlowServiceTracker) {
			service := new(svcmock.MockDeviceManagerService)
			registerHandlerFlowMockMethods(&service.Mock, reflect.TypeOf((*services.DeviceManagerService)(nil)).Elem(), tracker)
			NewDeviceManagerHTTPLayer(root, service, options)
		},
		"dms-manager": func(root *gin.RouterGroup, tracker *handlerFlowServiceTracker) {
			service := new(svcmock.MockDMSManagerService)
			registerHandlerFlowMockMethods(&service.Mock, reflect.TypeOf((*services.DMSManagerService)(nil)).Elem(), tracker)
			NewDMSManagerHTTPLayer(logrus.NewEntry(logrus.New()), root, service, options)
		},
		"va": func(root *gin.RouterGroup, tracker *handlerFlowServiceTracker) {
			service := new(svcmock.MockVAService)
			registerHandlerFlowMockMethods(&service.Mock, reflect.TypeOf((*services.CRLService)(nil)).Elem(), tracker)
			NewValidationRoutes(logrus.NewEntry(logrus.New()), root, nil, service, options)
		},
		"alerts": func(root *gin.RouterGroup, tracker *handlerFlowServiceTracker) {
			NewAlertsHTTPLayer(root, &handlerFlowAlertsService{tracker: tracker}, options)
		},
	}

	for _, group := range tenantAdministrativeEndpointGroups {
		group := group
		t.Run(group.service, func(t *testing.T) {
			router := gin.New()
			tracker := &handlerFlowServiceTracker{}
			registrars[group.service](router.Group("/"), tracker)

			for _, endpoint := range group.endpoints {
				endpoint := endpoint
				t.Run(endpoint.path, func(t *testing.T) {
					path := "/api/v2/tenants/" + handlerFlowTenantA + endpointMatrixConcretePath(endpoint.path)
					body := "{}"
					if group.service == "kms" && endpoint.path == "/keys/import" {
						body = keyImportBody
					}
					beforeA := tracker.calls
					responseA := httptest.NewRecorder()
					requestA := httptest.NewRequest(endpoint.method, path, strings.NewReader(body))
					requestA.Header.Set("Content-Type", "application/json")
					router.ServeHTTP(responseA, requestA)
					if tracker.calls <= beforeA {
						t.Fatalf("allowed tenant request did not reach the service; status=%d body=%s", responseA.Code, responseA.Body.String())
					}
					for _, tenantID := range tracker.tenantIDs[beforeA:] {
						if tenantID != handlerFlowTenantA {
							t.Errorf("service received tenant %q, want %q", tenantID, handlerFlowTenantA)
						}
					}

					beforeB := tracker.calls
					foreignPath := strings.Replace(path, "/tenants/"+handlerFlowTenantA+"/", "/tenants/"+handlerFlowTenantB+"/", 1)
					responseB := httptest.NewRecorder()
					requestB := httptest.NewRequest(endpoint.method, foreignPath, strings.NewReader(body))
					requestB.Header.Set("Content-Type", "application/json")
					router.ServeHTTP(responseB, requestB)
					if responseB.Code != http.StatusForbidden {
						t.Fatalf("foreign tenant request should be denied before controller, got status=%d body=%s", responseB.Code, responseB.Body.String())
					}
					if tracker.calls != beforeB {
						t.Errorf("foreign tenant request reached service: calls before=%d after=%d", beforeB, tracker.calls)
					}
				})
			}
		})
	}
}

type handlerFlowServiceTracker struct {
	calls     int
	tenantIDs []string
}

func registerHandlerFlowMockMethods(serviceMock *mock.Mock, serviceType reflect.Type, tracker *handlerFlowServiceTracker) {
	for methodIndex := 0; methodIndex < serviceType.NumMethod(); methodIndex++ {
		method := serviceType.Method(methodIndex)
		arguments := make([]interface{}, method.Type.NumIn())
		arguments[0] = mock.MatchedBy(func(ctx context.Context) bool {
			tenant, err := core.RequireTenantContext(ctx)
			if err != nil || !tenant.Validated {
				return false
			}
			tracker.calls++
			tracker.tenantIDs = append(tracker.tenantIDs, tenant.TenantID)
			return tenant.TenantID == handlerFlowTenantA
		})
		for argumentIndex := 1; argumentIndex < method.Type.NumIn(); argumentIndex++ {
			arguments[argumentIndex] = mock.Anything
		}

		returns := make([]interface{}, method.Type.NumOut())
		for returnIndex := 0; returnIndex < method.Type.NumOut(); returnIndex++ {
			returns[returnIndex] = handlerFlowDefaultReturn(method.Name, method.Type.Out(returnIndex))
		}
		serviceMock.On(method.Name, arguments...).Return(returns...).Maybe()
	}
}

func handlerFlowDefaultReturn(methodName string, returnType reflect.Type) interface{} {
	if methodName == "SignatureSign" && returnType.Kind() == reflect.Slice {
		return new([]byte)
	}
	if methodName == "GetVARoles" {
		roles := []*models.VARole{}
		return &roles
	}
	if returnType.Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		return nil
	}
	switch returnType.Kind() {
	case reflect.Pointer:
		return reflect.New(returnType.Elem()).Interface()
	case reflect.Slice:
		return reflect.MakeSlice(returnType, 0, 0).Interface()
	case reflect.Map:
		return reflect.MakeMap(returnType).Interface()
	default:
		return reflect.Zero(returnType).Interface()
	}
}

type routesTenantOptions struct {
	routes  TenantRouteOptions
	assertA func(*testing.T)
	assertB func(*testing.T)
}

func validatedHandlerFlowContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		tenant, err := core.RequireTenantContext(ctx)
		return err == nil && tenant.TenantID == handlerFlowTenantA && tenant.Validated
	})
}
