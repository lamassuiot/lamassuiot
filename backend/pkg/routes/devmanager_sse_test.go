package routes

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/controllers"
	authzcore "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/sirupsen/logrus"
	tmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// allowAllEngine authorizes every request, so the test reaches the SSE handler through the real route wiring.
type allowAllEngine struct {
	authzcore.AuthzEngine
}

func (allowAllEngine) MatchAndAuthorize(context.Context, string, string, string, string, string, string, map[string]string) (bool, []string, error) {
	return true, nil, nil
}

// TestDeviceSSEThroughGinEngineOutlivesWriteTimeout streams through NewGinEngine (otel, logger and gindump
// wrappers around the response writer) behind a server whose WriteTimeout is far shorter than the stream. It
// fails if any wrapper hides the underlying net/http writer from http.ResponseController, because the
// handler's per-write deadline can then no longer replace the server's.
func TestDeviceSSEThroughGinEngineOutlivesWriteTimeout(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	hub := controllers.NewDeviceEventSSEHub(logger, controllers.DeviceEventSSEHubOptions{})

	svc := &mock.MockDeviceManagerService{}
	svc.On("GetDeviceByID", tmock.Anything, tmock.MatchedBy(func(in services.GetDeviceByIDInput) bool { return in.ID == "dev-1" })).
		Return(&models.Device{ID: "dev-1"}, nil)

	engine := NewGinEngine(logger)
	engine.Use(func(c *gin.Context) {
		c.Set("lamassu.io/ctx/auth-type", "jwt")
		c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
		c.Next()
	})
	registerDeviceManagerRoutes(engine.Group("/api/devmanager"), svc, hub, allowAllEngine{}, logger)

	srv := httptest.NewUnstartedServer(engine)
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/devmanager/v1/devices/dev-1/events", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	time.AfterFunc(500*time.Millisecond, func() {
		hub.Publish("dev-1", "device.update.status", map[string]string{"k": "v"})
	})

	got := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "data: ") {
				got <- scanner.Text()
				return
			}
		}
		close(got)
	}()

	select {
	case line, ok := <-got:
		require.True(t, ok, "stream ended before the event arrived")
		require.Equal(t, `data: {"event_type":"device.update.status","data":{"k":"v"}}`, line)
	case <-time.After(3 * time.Second):
		t.Fatal("no event received")
	}
}
