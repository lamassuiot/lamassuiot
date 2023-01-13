package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
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
	Insecure      bool
}

type jwtAuthRoundTripper struct {
	username          string
	password          string
	authUrl           *url.URL
	serverRootCAs     *x509.CertPool
	authServerRootCAs *x509.CertPool
	token             string
	insecure          bool
	insecureAuth      bool
}

func NewJWTAuthTransport(username string, password string, authUrl *url.URL, rootCAs *x509.CertPool, authRootCAs *x509.CertPool, insecure bool, insecureAuth bool) jwtAuthRoundTripper {
	return jwtAuthRoundTripper{
		username:          username,
		password:          password,
		authUrl:           authUrl,
		serverRootCAs:     rootCAs,
		authServerRootCAs: authRootCAs,
		insecure:          insecure,
		insecureAuth:      insecureAuth,
	}
}

func (t jwtAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Do work before the request is sent
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: t.serverRootCAs,
		},
	}

	if t.insecure {
		tr.TLSClientConfig.InsecureSkipVerify = true
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
	if t.insecureAuth {
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	var conf = oauth2.Config{
		ClientID: "frontend",
		Endpoint: oauth2.Endpoint{
			AuthURL:  t.authUrl.String() + "/auth/realms/lamassu/protocol/openid-connect/auth",
			TokenURL: t.authUrl.String() + "/auth/realms/lamassu/protocol/openid-connect/token",
		},
	}

	token, err := conf.PasswordCredentialsToken(context.Background(), t.username, t.password)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
