package basiclogger

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestUseLoggerEnrichesAccessLog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var output bytes.Buffer
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(helpers.LogFormatter)
	logger.SetOutput(&output)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), core.LamassuContextKeySource, "dashboard")
		ctx = context.WithValue(ctx, core.LamassuContextKeyAuthID, "principal-1")
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}, UseLogger(logrus.NewEntry(logger)))
	router.GET("/policies", func(c *gin.Context) {
		c.Status(200)
	})

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/policies", nil))

	require.Contains(t, output.String(), "dashboard")
	require.Contains(t, output.String(), "principal-1")
	require.True(t, strings.Contains(output.String(), "/policies"))
}
