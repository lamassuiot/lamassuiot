package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	lamassucore "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeEngine struct {
	err               error
	authorized        bool
	matchedPrincipals []string
	filterSQL         string
}

func (e *fakeEngine) Authorize(_ context.Context, principalID, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error) {
	return e.authorized, e.err
}

func (e *fakeEngine) GetFilter(_ context.Context, principalID, namespace, schemaName, entityType string) (string, error) {
	return e.filterSQL, e.err
}

func (e *fakeEngine) MatchAndAuthorize(_ context.Context, authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, []string, error) {
	return e.authorized, e.matchedPrincipals, e.err
}

func (e *fakeEngine) MatchAndGetFilter(_ context.Context, authType, authMaterial, namespace, schemaName, entityType string) (string, []string, error) {
	return e.filterSQL, e.matchedPrincipals, e.err
}

type fakeHTTPStatusError struct {
	status int
}

func (e fakeHTTPStatusError) Error() string {
	return http.StatusText(e.status)
}

func (e fakeHTTPStatusError) HTTPStatusCode() int {
	return e.status
}

func TestAuthzCheckReturnsUnauthorizedFromAuthzService(t *testing.T) {
	router := testRouterWithAuthzInputs()
	err := fmt.Errorf("remote match and authorize failed: %w", fakeHTTPStatusError{status: http.StatusUnauthorized})
	middleware := NewSimpleAuthzMiddleware(&fakeEngine{err: err}, "pki", "devicemanager", "device", testLogger())

	router.GET("/devices/:id", middleware.AuthzCheck("read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/devices/device-1", nil)
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestAuthListCheckReturnsUnauthorizedFromAuthzService(t *testing.T) {
	router := testRouterWithAuthzInputs()
	err := fmt.Errorf("remote match and get filter failed: %w", fakeHTTPStatusError{status: http.StatusUnauthorized})
	middleware := NewSimpleAuthzMiddleware(&fakeEngine{err: err}, "pki", "devicemanager", "device", testLogger())

	router.GET("/devices", middleware.AuthListCheck(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/devices", nil)
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func testRouterWithAuthzInputs() *gin.Engine {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("lamassu.io/ctx/auth-type", "jwt")
		c.Set("lamassu.io/ctx/auth-credential-string", "token")
		c.Next()
	})

	return router
}

func TestAuthzCheckPropagatesMatchedPrincipalsToRequestContext(t *testing.T) {
	router := testRouterWithAuthzInputs()
	engine := &fakeEngine{authorized: true, matchedPrincipals: []string{"principal-a", "principal-b"}}
	mw := NewSimpleAuthzMiddleware(engine, "pki", "devicemanager", "device", testLogger())

	var capturedPrincipals interface{}
	router.GET("/devices/:id", mw.AuthzCheck("read"), func(c *gin.Context) {
		capturedPrincipals = c.Request.Context().Value(lamassucore.LamassuContextKeyMatchedPrincipals)
		c.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/devices/device-1", nil)
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, []string{"principal-a", "principal-b"}, capturedPrincipals)
}

func TestAuthListCheckPropagatesMatchedPrincipalsToRequestContext(t *testing.T) {
	router := testRouterWithAuthzInputs()
	engine := &fakeEngine{matchedPrincipals: []string{"principal-x"}, filterSQL: "1=1"}
	mw := NewSimpleAuthzMiddleware(engine, "pki", "devicemanager", "device", testLogger())

	var capturedPrincipals interface{}
	router.GET("/devices", mw.AuthListCheck(), func(c *gin.Context) {
		capturedPrincipals = c.Request.Context().Value(lamassucore.LamassuContextKeyMatchedPrincipals)
		c.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/devices", nil)
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, []string{"principal-x"}, capturedPrincipals)
}

func testLogger() *logrus.Entry {
	logger := logrus.New()
	logger.SetOutput(httptest.NewRecorder())

	return logrus.NewEntry(logger)
}
