package helpers

import (
	"net/http"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
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
