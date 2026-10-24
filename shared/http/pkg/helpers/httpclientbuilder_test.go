package helpers

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/sirupsen/logrus"
)

func TestBuildHTTPClientWithTLSOptions(t *testing.T) {
	// Create a mock HTTP client
	mockClient := &http.Client{}

	// Test case 1: InsecureSkipVerify is true
	cfg := cconfig.TLSConfig{
		InsecureSkipVerify: true,
	}
	client, err := BuildHTTPClientWithTLSOptions(mockClient, cfg)
	if err != nil {
		t.Errorf("BuildHTTPClientWithTLSOptions failed with error: %v", err)
	}

	// Verify that the returned client has InsecureSkipVerify set to true
	tlsConfig := client.Transport.(*http.Transport).TLSClientConfig
	if !tlsConfig.InsecureSkipVerify {
		t.Error("BuildHTTPClientWithTLSOptions did not set InsecureSkipVerify to true")
	}

	// Test case 3: CACertificateFile is empty
	cfg = cconfig.TLSConfig{}
	client, err = BuildHTTPClientWithTLSOptions(mockClient, cfg)
	if err != nil {
		t.Errorf("BuildHTTPClientWithTLSOptions failed with error: %v", err)
	}

	// Verify that the returned client has InsecureSkipVerify set to true
	tlsConfig = client.Transport.(*http.Transport).TLSClientConfig
	if tlsConfig.InsecureSkipVerify {
		t.Error("BuildHTTPClientWithTLSOptions is set InsecureSkipVerify to true")
	}
}

func TestBuildHTTPClientWithTracerLogger(t *testing.T) {
	// Create a mock HTTP client
	mockClient := &http.Client{}

	// Create a mock logger
	mockLogger := logrus.NewEntry(logrus.New())

	// Test case 1: cli.Transport is nil
	client, err := BuildHTTPClientWithTracerLogger(mockClient, mockLogger)
	if err != nil {
		t.Errorf("BuildHTTPClientWithTracerLogger failed with error: %v", err)
	}

	// Verify that the returned client has the loggingRoundTripper as the Transport
	if _, ok := client.Transport.(loggingRoundTripper); !ok {
		t.Error("BuildHTTPClientWithTracerLogger did not set the loggingRoundTripper as the Transport")
	}

	// Test case 2: cli.Transport is not nil
	mockTransport := &http.Transport{}
	mockClient.Transport = mockTransport

	client, err = BuildHTTPClientWithTracerLogger(mockClient, mockLogger)
	if err != nil {
		t.Errorf("BuildHTTPClientWithTracerLogger failed with error: %v", err)
	}

	// Verify that the returned client has the loggingRoundTripper as the Transport
	if _, ok := client.Transport.(loggingRoundTripper); !ok {
		t.Error("BuildHTTPClientWithTracerLogger did not set the loggingRoundTripper as the Transport")
	}
}

// The trace dump buffers only a bounded prefix of the response body, so the
// caller must still receive the complete body.
func TestLoggingRoundTripperPreservesLargeBodies(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 3<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	for _, level := range []logrus.Level{logrus.InfoLevel, logrus.TraceLevel} {
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		logger.SetLevel(level)

		client, err := BuildHTTPClientWithTracerLogger(&http.Client{}, logrus.NewEntry(logger))
		if err != nil {
			t.Fatalf("BuildHTTPClientWithTracerLogger failed with error: %v", err)
		}

		res, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request failed at level %s: %v", level, err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatalf("reading body failed at level %s: %v", level, err)
		}
		if !bytes.Equal(body, payload) {
			t.Errorf("body altered at level %s: got %d bytes, want %d", level, len(body), len(payload))
		}
	}
}
