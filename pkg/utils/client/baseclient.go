package client

import (
	"bytes"
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
)

type BaseClient interface {
	NewRequest(method string, path string, body interface{}) (*http.Request, error)
	Do(req *http.Request) (interface{}, *http.Response, error)
}

type ClientConfig struct {
	BaseURL    *url.URL
	httpClient *http.Client
}

func NewBaseClient(config ClientConfiguration) (BaseClient, error) {
	caPem, err := ioutil.ReadFile(config.CACertificate)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPem)

	tr := &http.Transport{}
	httpClient := &http.Client{Transport: tr}

	if config.AuthMethod == MutualTLS {
		authConfig, ok := config.AuthMethodConfig.(*MutualTLSConfig)
		if !ok {
			return nil, errors.New("invalid client configuration, missing AuthMethodConfig")
		}
		cert, err := tls.LoadX509KeyPair(authConfig.ClientCert, authConfig.ClientKey)
		if err != nil {
			return nil, err
		}
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      certPool,
					Certificates: []tls.Certificate{cert},
				},
			},
		}
	} else if config.AuthMethod == JWT {
		authConfig, ok := config.AuthMethodConfig.(*JWTConfig)
		if !ok {
			return nil, errors.New("invalid client configuration, missing JWTConfig")
		}

		authCAPem, err := ioutil.ReadFile(config.CACertificate)
		if err != nil {
			return nil, err
		}

		authCertPool := x509.NewCertPool()
		authCertPool.AppendCertsFromPEM(authCAPem)

		rt := jwtAuthRoundTripper{
			AuthRootCAs: authCertPool,
			Username:    authConfig.Username,
			Password:    authConfig.Password,
			URL:         authConfig.URL,
		}
		httpClient = &http.Client{Transport: rt}
	} else {
		return nil, errors.New("invalid auth type")
	}

	return &ClientConfig{
		BaseURL:    config.URL,
		httpClient: httpClient,
	}, nil
}

func (c *ClientConfig) NewRequest(method string, path string, body interface{}) (*http.Request, error) {
	rel := &url.URL{Path: path}
	u := c.BaseURL.ResolveReference(rel)
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *ClientConfig) Do(req *http.Request) (interface{}, *http.Response, error) {
	var v interface{}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		return nil, resp, errors.New("Response with status code: " + strconv.Itoa(resp.StatusCode) + "")
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&v)
	return v, resp, err
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
