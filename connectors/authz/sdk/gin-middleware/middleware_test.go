package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeEngine struct {
	err error
}

func (e *fakeEngine) Authorize(_ context.Context, principalID, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error) {
	return false, e.err
}

func (e *fakeEngine) GetFilter(_ context.Context, principalID, namespace, schemaName, entityType string) (string, error) {
	return "", e.err
}

func (e *fakeEngine) MatchAndAuthorize(_ context.Context, authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, []string, error) {
	return false, nil, e.err
}

func (e *fakeEngine) MatchAndGetFilter(_ context.Context, authType, authMaterial, namespace, schemaName, entityType string) (string, []string, error) {
	return "", nil, e.err
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

func testLogger() *logrus.Entry {
	logger := logrus.New()
	logger.SetOutput(httptest.NewRecorder())

	return logrus.NewEntry(logger)
}
