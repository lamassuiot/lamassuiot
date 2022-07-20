package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
)

type BaseClient interface {
	NewRequest(method string, path string, body []byte) (*http.Request, error)
	Do(req *http.Request) (*http.Response, error)
}

type ClientConfig struct {
	BaseURL    string
	httpClient *http.Client
}

func NewBaseClient(url string, httpClient *http.Client) BaseClient {
	return &ClientConfig{
		BaseURL:    url,
		httpClient: httpClient,
	}
}

func (c *ClientConfig) NewRequest(method string, path string, body []byte) (*http.Request, error) {
	url := "http://" + c.BaseURL + path
	var buf io.ReadWriter
	if body != nil {
		buf = bytes.NewBuffer(body)
	}
	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}
func (c *ClientConfig) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("Response with status code: " + strconv.Itoa(resp.StatusCode))
	}

	return resp, err
}
