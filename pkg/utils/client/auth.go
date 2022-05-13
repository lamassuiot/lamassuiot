package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type AuthMethod int64

const (
	JWT AuthMethod = iota
	MutualTLS
)

type MutualTLSConfig struct {
	ClientCert string
	ClientKey  string
}

type JWTConfig struct {
	Username      string
	Password      string
	URL           *url.URL
	CACertificate string
}

type jwtAuthRoundTripper struct {
	Username    string
	Password    string
	URL         *url.URL
	AuthRootCAs *x509.CertPool
	Token       string
}

func (t jwtAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Do work before the request is sent
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: t.AuthRootCAs,
		},
	}

	if t.Token == "" {
		token, err := t.getJWT()
		if err == nil {
			t.Token = token
		}
	}

	req.Header.Add("Authorization", "Bearer "+t.Token)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Do work after the response is received
	return resp, err
}

func (t jwtAuthRoundTripper) getJWT() (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: t.AuthRootCAs,
		},
	}

	httpClient := &http.Client{Transport: tr}

	t.URL.Path = "/auth/realms/lamassu/protocol/openid-connect/token/"
	payload := strings.NewReader("grant_type=password&client_id=frontend&username=" + t.Username + "&password=" + t.Password)
	request, err := http.NewRequest("POST", t.URL.String(), payload)
	if err != nil {
		return "", err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient.Do(request)
	if err != nil {
		return "", err
	}
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	var jsonContent map[string]interface{}
	json.Unmarshal(bodyBytes, &jsonContent)
	return jsonContent["access_token"].(string), nil
}
