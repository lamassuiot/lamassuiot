package controllers

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	tmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newQuietHub is newTestHub without the "channel full" warnings the stalled-client test provokes on purpose.
func newQuietHub(opts DeviceEventSSEHubOptions) *DeviceEventSSEHub {
	l := logrus.New()
	l.SetLevel(logrus.ErrorLevel)
	return NewDeviceEventSSEHub(logrus.NewEntry(l), opts)
}

// newSSEMockService returns a device manager that knows "dev-1" and answers ErrDeviceNotFound for "missing".
func newSSEMockService() *mock.MockDeviceManagerService {
	svc := &mock.MockDeviceManagerService{}
	svc.On("GetDeviceByID", tmock.Anything, tmock.MatchedBy(func(in services.GetDeviceByIDInput) bool { return in.ID == "dev-1" })).
		Return(&models.Device{ID: "dev-1"}, nil)
	svc.On("GetDeviceByID", tmock.Anything, tmock.MatchedBy(func(in services.GetDeviceByIDInput) bool { return in.ID == "missing" })).
		Return((*models.Device)(nil), errs.ErrDeviceNotFound)
	return svc
}

// newSSETestServer serves streamDeviceEventsSSE on GET /devices/:id/events behind a real net/http server whose
// WriteTimeout is writeTimeout, so the tests exercise the same deadline machinery as production.
func newSSETestServer(t *testing.T, svc services.DeviceManagerService, hub *DeviceEventSSEHub, writeTimeout time.Duration, tune func(*devManagerHttpRoutes)) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)

	r := NewDeviceManagerHttpRoutesWithSSE(svc, hub)
	if tune != nil {
		tune(r)
	}

	engine := gin.New()
	engine.GET("/devices/:id/events", func(c *gin.Context) {
		r.streamDeviceEventsSSE(c, c.Param("id"))
	})

	srv := httptest.NewUnstartedServer(engine)
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func waitForSubscribers(t *testing.T, hub *DeviceEventSSEHub, want int, within time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool { return hub.subscriberCount() == want }, within, 5*time.Millisecond,
		"expected %d subscribers, have %d", want, hub.subscriberCount())
}

func openSSE(t *testing.T, ctx context.Context, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

type sseLine struct {
	text string
	at   time.Duration // since start
}

// readSSELines reads resp.Body line by line and sends each line with its arrival time. The returned channel is
// closed on EOF or read error; eofAt then holds the time the stream ended and endErr the error that ended it
// (io.EOF for a clean close).
func readSSELines(resp *http.Response, start time.Time) (lines <-chan sseLine, eofAt func() time.Duration, endErr func() error) {
	out := make(chan sseLine, 256)
	var mu sync.Mutex
	var end time.Duration
	var last error
	go func() {
		defer close(out)
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if line != "" {
				out <- sseLine{text: strings.TrimRight(line, "\r\n"), at: time.Since(start)}
			}
			if err != nil {
				mu.Lock()
				end = time.Since(start)
				last = err
				mu.Unlock()
				return
			}
		}
	}()
	return out, func() time.Duration {
			mu.Lock()
			defer mu.Unlock()
			return end
		}, func() error {
			mu.Lock()
			defer mu.Unlock()
			return last
		}
}

func TestSSEStreamOutlivesServerWriteTimeout(t *testing.T) {
	hub := newQuietHub(DeviceEventSSEHubOptions{})
	srv := newSSETestServer(t, newSSEMockService(), hub, 200*time.Millisecond, func(r *devManagerHttpRoutes) {
		r.sseKeepaliveInterval = 50 * time.Millisecond
		r.sseWriteWindow = time.Second
		r.sseMaxStreamDuration = time.Second
	})

	start := time.Now()
	resp := openSSE(t, context.Background(), srv.URL+"/devices/dev-1/events")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	time.AfterFunc(400*time.Millisecond, func() {
		hub.Publish("dev-1", "device.update.status", map[string]string{"k": "v"})
	})

	lines, eofAt, endErr := readSSELines(resp, start)
	var lateKeepalive, gotData bool
	timeout := time.After(5 * time.Second)
loop:
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				break loop
			}
			if l.text == ": keepalive" && l.at > 300*time.Millisecond {
				lateKeepalive = true
			}
			if l.text == `data: {"event_type":"device.update.status","data":{"k":"v"}}` {
				gotData = true
			}
		case <-timeout:
			t.Fatal("stream did not end")
		}
	}

	assert.True(t, lateKeepalive, "expected a keepalive after 300ms; the server WriteTimeout must not cut the stream")
	assert.True(t, gotData, "expected the published event")
	end := eofAt()
	assert.GreaterOrEqual(t, end, time.Second, "stream ended before its lifetime")
	assert.LessOrEqual(t, end, 1500*time.Millisecond, "stream outlived lifetime + jitter")
	assert.Equal(t, io.EOF, endErr(), "the stream must end with a clean close, not a reset")

	waitForSubscribers(t, hub, 0, time.Second)
}

// The terminating chunk is written under the deadline of the last write; with a write window shorter than the
// keepalive that deadline has expired by the time the lifetime ends, so the handler must renew it.
func TestSSELifetimeEndClosesCleanlyWithShortWriteWindow(t *testing.T) {
	hub := newQuietHub(DeviceEventSSEHubOptions{})
	srv := newSSETestServer(t, newSSEMockService(), hub, 0, func(r *devManagerHttpRoutes) {
		r.sseKeepaliveInterval = time.Hour
		r.sseWriteWindow = 50 * time.Millisecond
		r.sseMaxStreamDuration = 300 * time.Millisecond
	})

	start := time.Now()
	resp := openSSE(t, context.Background(), srv.URL+"/devices/dev-1/events")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	lines, _, endErr := readSSELines(resp, start)
	timeout := time.After(5 * time.Second)
	for done := false; !done; {
		select {
		case _, ok := <-lines:
			done = !ok
		case <-timeout:
			t.Fatal("stream did not end")
		}
	}
	assert.Equal(t, io.EOF, endErr(), "the lifetime end must close the stream cleanly even after the last write deadline expired")
	waitForSubscribers(t, hub, 0, time.Second)
}

func TestSSEClientCloseReleasesSubscription(t *testing.T) {
	hub := newQuietHub(DeviceEventSSEHubOptions{})
	srv := newSSETestServer(t, newSSEMockService(), hub, 0, func(r *devManagerHttpRoutes) {
		r.sseKeepaliveInterval = 20 * time.Millisecond
		r.sseWriteWindow = time.Second
		r.sseMaxStreamDuration = time.Hour
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp := openSSE(t, ctx, srv.URL+"/devices/dev-1/events")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	waitForSubscribers(t, hub, 1, time.Second)

	lines, _, _ := readSSELines(resp, time.Now())
	select {
	case l := <-lines:
		require.Equal(t, ": keepalive", l.text)
	case <-time.After(2 * time.Second):
		t.Fatal("no keepalive received")
	}

	cancel()
	waitForSubscribers(t, hub, 0, time.Second)
}

func TestSSEStalledClientEndsWithinWriteWindow(t *testing.T) {
	hub := newQuietHub(DeviceEventSSEHubOptions{})
	// No server WriteTimeout: only the handler's per-write deadline may end the stream.
	srv := newSSETestServer(t, newSSEMockService(), hub, 0, func(r *devManagerHttpRoutes) {
		r.sseKeepaliveInterval = time.Hour
		r.sseWriteWindow = 200 * time.Millisecond
		r.sseMaxStreamDuration = time.Hour
	})

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("GET /devices/dev-1/events HTTP/1.1\r\nHost: test\r\nAccept: text/event-stream\r\n\r\n"))
	require.NoError(t, err)

	// Read the response headers, then stop reading altogether.
	reader := bufio.NewReader(conn)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" {
			break
		}
	}
	waitForSubscribers(t, hub, 1, time.Second)

	done := make(chan struct{})
	defer close(done)
	payload := strings.Repeat("x", 256*1024)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				hub.Publish("dev-1", "device.update.status", payload)
			}
		}
	}()

	waitForSubscribers(t, hub, 0, 5*time.Second)
}

func TestSSESubscriberLimit(t *testing.T) {
	hub := newQuietHub(DeviceEventSSEHubOptions{MaxSubscribers: 1})
	svc := newSSEMockService()
	srv := newSSETestServer(t, svc, hub, 0, func(r *devManagerHttpRoutes) {
		r.sseKeepaliveInterval = time.Hour
		r.sseWriteWindow = time.Second
		r.sseMaxStreamDuration = time.Hour
	})
	url := srv.URL + "/devices/dev-1/events"

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	respA := openSSE(t, ctxA, url)
	defer respA.Body.Close()
	require.Equal(t, http.StatusOK, respA.StatusCode)

	respB := openSSE(t, context.Background(), url)
	defer respB.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, respB.StatusCode)
	assert.Equal(t, "10", respB.Header.Get("Retry-After"))
	var body map[string]any
	require.NoError(t, json.NewDecoder(respB.Body).Decode(&body))
	assert.Contains(t, body, "err")

	cancelA()
	waitForSubscribers(t, hub, 0, time.Second)

	respC := openSSE(t, context.Background(), url)
	defer respC.Body.Close()
	assert.Equal(t, http.StatusOK, respC.StatusCode)
	assert.Equal(t, "text/event-stream", respC.Header.Get("Content-Type"))

	// Requests A and C reach the device lookup; B is refused by the hub before it.
	svc.AssertNumberOfCalls(t, "GetDeviceByID", 2)
}

func TestSSELookupFailureReleasesSlot(t *testing.T) {
	hub := newQuietHub(DeviceEventSSEHubOptions{MaxSubscribers: 1})
	srv := newSSETestServer(t, newSSEMockService(), hub, 0, func(r *devManagerHttpRoutes) {
		r.sseKeepaliveInterval = time.Hour
		r.sseWriteWindow = time.Second
		r.sseMaxStreamDuration = time.Hour
	})

	respMissing := openSSE(t, context.Background(), srv.URL+"/devices/missing/events")
	defer respMissing.Body.Close()
	assert.Equal(t, http.StatusNotFound, respMissing.StatusCode)
	waitForSubscribers(t, hub, 0, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	respOK := openSSE(t, ctx, srv.URL+"/devices/dev-1/events")
	defer respOK.Body.Close()
	assert.Equal(t, http.StatusOK, respOK.StatusCode)
}
