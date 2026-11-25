package gindump

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDumpEngine(dump *string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(DumpWithOptions(true, true, true, true, func(s string) { *dump = s }))
	return r
}

func TestDumpDoesNotCacheEventStreamBody(t *testing.T) {
	var dump string
	r := newDumpEngine(&dump)
	r.GET("/stream", func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		_, _ = c.Writer.Write([]byte("data: secret-payload\n\n"))
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stream", nil))

	assert.Contains(t, w.Body.String(), "secret-payload")
	assert.NotContains(t, dump, "secret-payload")
}

func TestDumpStillCachesJSONBody(t *testing.T) {
	var dump string
	r := newDumpEngine(&dump)
	r.GET("/json", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"k": "visible"})
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/json", nil))

	assert.Contains(t, w.Body.String(), "visible")
	assert.Contains(t, dump, "visible")
}

func TestBodyWriterUnwrapReachesNetHTTP(t *testing.T) {
	var dump string
	r := newDumpEngine(&dump)
	deadlineErr := make(chan error, 1)
	r.GET("/deadline", func(c *gin.Context) {
		deadlineErr <- http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(time.Second))
		c.Status(http.StatusNoContent)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/deadline")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case err := <-deadlineErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal(strings.TrimSpace("handler did not run"))
	}
}
