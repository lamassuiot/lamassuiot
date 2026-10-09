package routes

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	smock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRemainingBackendOpenAPIContracts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := logrus.NewEntry(logrus.New())
	for _, name := range []string{"alerts", "dms-manager"} {
		for _, authenticated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/authenticated=%v", name, authenticated), func(t *testing.T) {
				router := gin.New()
				if authenticated {
					router.Use(func(c *gin.Context) {
						c.Set("lamassu.io/ctx/auth-type", "jwt")
						c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
						c.Next()
					})
				}
				engine := &contractTestEngine{}
				var contract *middleware.ContractRouter
				count := 4
				if name == "alerts" {
					contract = registerAlertsRoutes(logger, router.Group("/api/alerts"), nil, engine)
				} else {
					contract = registerDMSManagerRoutes(logger, router.Group("/api/dmsmanager"), nil, engine)
					count = 17
				}
				require.Len(t, contract.Declarations(), count)
				require.NoError(t, contract.ValidateRoutes(router.Routes()))
				spec, err := os.ReadFile("../specs/" + name + "-openapi.yaml")
				require.NoError(t, err)
				require.NoError(t, contract.ValidateOpenAPI(strings.NewReader(string(spec))))
				for _, route := range contract.Declarations() {
					if route.Authz.Check == "public" || route.Authz.Check == "est" {
						continue
					} // Protocol routes are exercised below.
					t.Run(route.Method+" "+route.Path, func(t *testing.T) {
						engine.calls = 0
						path := strings.NewReplacer(":userId", "user-456", ":subId", "sub-123", ":id", "dms-123").Replace(route.Path)
						response := httptest.NewRecorder()
						router.ServeHTTP(response, httptest.NewRequest(route.Method, path, nil))
						if !authenticated {
							assert.Equal(t, 401, response.Code)
							assert.Zero(t, engine.calls)
							return
						}
						status := 403
						if route.Authz.Check == "filter" {
							status = 500
						}
						assert.Equal(t, status, response.Code)
						require.Equal(t, 1, engine.calls)
						assert.Equal(t, route.Authz, engine.declaration)
						var key map[string]string
						if route.Authz.EntityType == "subscription" && route.Authz.Action == "delete" {
							key = map[string]string{"id": "sub-123"}
						}
						if route.Authz.EntityType == "dms" && route.Authz.Action != "create" && route.Authz.Action != "bind-identity" && route.Authz.Check != "filter" {
							key = map[string]string{"id": "dms-123"}
						}
						assert.Equal(t, key, engine.key)
					})
				}
				router.GET(strings.TrimSuffix(contract.Declarations()[0].Path, "/latest")+"/untracked", func(c *gin.Context) {})
				assert.Error(t, contract.ValidateRoutes(router.Routes()))
			})
		}
	}
}

func TestDMSAllESTOperationsUseProtocolAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	csr, err := os.ReadFile("../helpers/testdata/samplecsr.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(csr)
	require.NotNil(t, block)
	body := base64.StdEncoding.EncodeToString(block.Bytes)
	router := gin.New()
	svc := new(smock.MockESTService)
	contract := middleware.NewContractRouter(router.Group("/api/dmsmanager"))
	RegisterESTRoutes(logrus.NewEntry(logrus.New()), contract, svc)
	require.Len(t, contract.Declarations(), 8)
	for _, route := range contract.Declarations() {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			// EST checks enrollment policy inside the service, without a domain JWT guard.
			svc.ExpectedCalls = nil
			svc.Calls = nil
			withAPS := strings.Contains(route.Path, ":aps")
			status := http.StatusBadRequest
			if withAPS {
				status = http.StatusInternalServerError
				switch {
				case strings.HasSuffix(route.Path, "/cacerts"):
					svc.On("CACerts", mock.Anything, "profile").Return([]*x509.Certificate{}, nil).Once()
					status = http.StatusOK
				case strings.HasSuffix(route.Path, "/simpleenroll"):
					svc.On("Enroll", mock.Anything, mock.Anything, "profile").Return((*x509.Certificate)(nil), errors.New("policy denied")).Once()
				case strings.HasSuffix(route.Path, "/simplereenroll"):
					svc.On("Reenroll", mock.Anything, mock.Anything, "profile").Return((*x509.Certificate)(nil), errors.New("policy denied")).Once()
				case strings.HasSuffix(route.Path, "/serverkeygen"):
					svc.On("ServerKeyGen", mock.Anything, mock.Anything, "profile").Return((*x509.Certificate)(nil), nil, errors.New("policy denied")).Once()
				}
			}
			req := httptest.NewRequest(route.Method, strings.ReplaceAll(route.Path, ":aps", "profile"), strings.NewReader(body))
			req.Header.Set("Content-Type", "application/pkcs10")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			assert.Equal(t, status, response.Code)
			if withAPS {
				svc.AssertExpectations(t)
			} else {
				assert.Empty(t, svc.Calls)
			}
		})
	}
}
