package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fallbackTestKey struct{}

// Handlers sometimes pass the *gin.Context itself as a context.Context. The
// engine must then resolve request-context values (such as the authz list
// filter), otherwise they silently disappear on the way to the storage layer.
func TestGinEngineResolvesRequestContextValuesThroughGinContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewGinEngine(logrus.NewEntry(logrus.New()))
	engine.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), fallbackTestKey{}, "from-request"))
		c.Next()
	})
	var got any
	engine.GET("/probe", func(c *gin.Context) {
		var ctx context.Context = c
		got = ctx.Value(fallbackTestKey{})
		c.Status(http.StatusNoContent)
	})

	engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe", nil))

	assert.Equal(t, "from-request", got)
}
