package client

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type BaseClient interface {
	NewRequest(method string, endpoint string, serverAddr string, aps string, contentType, transferEncoding string, accepts string, body io.Reader) (*http.Request, error)
	Do(req *http.Request) (*http.Response, []byte, error)
}

type ClientConfig struct {
	BaseURL    *url.URL
	httpClient *http.Client
}

func NewBaseClient(url *url.URL, httpClient *http.Client) BaseClient {
	return &ClientConfig{
		BaseURL:    url,
		httpClient: httpClient,
	}
}

func (c *ClientConfig) NewRequest(method string, endpoint string, serverAddr string, aps string, contentType, transferEncoding string, accepts string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.Uri(endpoint, serverAddr, aps), body)
	if err != nil {
		return nil, err
	}
	if accepts != "" {
		req.Header.Set("Accept", accepts)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if transferEncoding != "" {
		req.Header.Set("Content-Transfer-Encoding", transferEncoding)
	}

	if serverAddr != "" {
		req.Host = serverAddr
	}
	return req, err
}

func (c *ClientConfig) Do(req *http.Request) (*http.Response, []byte, error) {
	//var v interface{}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		return nil, nil, errors.New("Response with status code: " + strconv.Itoa(resp.StatusCode))
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}
	return resp, b, err
}

func (c *ClientConfig) Uri(endpoint string, serverAddr string, aps string) string {
	var builder strings.Builder

	builder.WriteString("https://")
	builder.WriteString(serverAddr)
	builder.WriteString("/.well-known/est")

	if aps != "" {
		builder.WriteRune('/')
		builder.WriteString(aps)
	}

	builder.WriteString(endpoint)

	return builder.String()
}
