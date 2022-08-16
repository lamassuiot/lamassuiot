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

type AuthMethod string

const (
	AuthMethodJWT       AuthMethod = "JWT"
	AuthMethodNone      AuthMethod = "None"
	AuthMethodMutualTLS AuthMethod = "MutualTLS"
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
	username          string
	password          string
	authUrl           *url.URL
	serverRootCAs     *x509.CertPool
	authServerRootCAs *x509.CertPool
	token             string
}

func NewJWTAuthTransport(username string, password string, authUrl *url.URL, rootCAs *x509.CertPool, authRootCAs *x509.CertPool) jwtAuthRoundTripper {
	return jwtAuthRoundTripper{
		username:          username,
		password:          password,
		authUrl:           authUrl,
		serverRootCAs:     rootCAs,
		authServerRootCAs: authRootCAs,
	}
}

func (t jwtAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Do work before the request is sent
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: t.serverRootCAs,
		},
	}

	if t.token == "" {
		token, err := t.getJWT()
		if err == nil {
			t.token = token
		}
	}

	req.Header.Add("Authorization", "Bearer "+t.token)

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
			RootCAs: t.authServerRootCAs,
		},
	}

	httpClient := &http.Client{Transport: tr}

	t.authUrl.Path = "/auth/realms/lamassu/protocol/openid-connect/token/"
	payload := strings.NewReader("grant_type=password&client_id=frontend&username=" + t.username + "&password=" + t.password)
	request, err := http.NewRequest("POST", t.authUrl.String(), payload)
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
