package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

type BaseClientConfigurationuration struct {
	URL              *url.URL
	AuthMethod       AuthMethod
	AuthMethodConfig interface{}
	CACertificate    string
	Insecure         bool
}

type ClientConfiguration struct {
	BaseURL    *url.URL
	httpClient *http.Client
}

type BaseClient interface {
	NewRequest(ctx context.Context, method string, path string, body interface{}) (*http.Request, error)
	Do(req *http.Request, response any) (*http.Response, error)
	Do2(req *http.Request) (*http.Response, error)
}

func NewBaseClient(config BaseClientConfigurationuration) (BaseClient, error) {
	tr := &http.Transport{}

	if config.URL.Scheme == "https" {
		certPool := x509.NewCertPool()
		if !config.Insecure {
			caPem, err := ioutil.ReadFile(config.CACertificate)
			if err != nil {
				return nil, err
			}

			certPool.AppendCertsFromPEM(caPem)
		}

		tr.TLSClientConfig = &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: config.Insecure,
		}
	}

	var httpClient *http.Client

	if config.AuthMethod == AuthMethodMutualTLS {
		authConfig, ok := config.AuthMethodConfig.(*MutualTLSConfig)
		if !ok {
			return nil, errors.New("invalid client configuration, missing AuthMethodConfig")
		}
		cert, err := tls.LoadX509KeyPair(authConfig.ClientCert, authConfig.ClientKey)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	} else if config.AuthMethod == AuthMethodJWT {
		authConfig, ok := config.AuthMethodConfig.(*JWTConfig)
		if !ok {
			return nil, errors.New("invalid client configuration, missing JWTConfig")
		}

		authCertPool := x509.NewCertPool()
		if !authConfig.Insecure {
			authCAPem, err := ioutil.ReadFile(config.CACertificate)
			if err != nil {
				return nil, err
			}

			authCertPool.AppendCertsFromPEM(authCAPem)
		}

		rt := NewJWTAuthTransport(
			authConfig.Username,
			authConfig.Password,
			authConfig.URL,
			tr.TLSClientConfig.RootCAs,
			authCertPool,
			config.Insecure,
			authConfig.Insecure,
		)

		httpClient = &http.Client{Transport: otelhttp.NewTransport(rt)}
	}

	if httpClient == nil {
		httpClient = &http.Client{Transport: otelhttp.NewTransport(tr)}
	}

	return &ClientConfiguration{
		BaseURL:    config.URL,
		httpClient: httpClient,
	}, nil
}

func (c *ClientConfiguration) NewRequest(ctx context.Context, method string, path string, body interface{}) (*http.Request, error) {
	u, err := url.JoinPath(c.BaseURL.String(), path)
	if err != nil {
		return nil, err
	}
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u, buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	spanContext := trace.SpanContextFromContext(ctx)
	req.Header.Set("x-request-id", fmt.Sprintf("%s:%s", spanContext.TraceID().String(), spanContext.SpanID().String()))
	return req, nil
}

func (c *ClientConfiguration) Do(req *http.Request, response any) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		body, err := io.ReadAll(resp.Body)
		bodyString := ""
		if err == nil {
			bodyString = string(body)
		}
		return resp, errors.New("Response with status code: " + strconv.Itoa(resp.StatusCode) + " Response body: " + bodyString)
	}

	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&response)
	return resp, err
}
func (c *ClientConfiguration) Do2(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

func ByteCountDecimal(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}
