package clients

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func BuildURL(cfg config.HTTPClient) string {
	return fmt.Sprintf("%s://%s:%d%s", cfg.Protocol, cfg.Hostname, cfg.Port, cfg.BasePath)
}

func BuildHTTPClient(cfg config.HTTPClient, clientName string) (*http.Client, error) {
	client := &http.Client{}

	caPool := helpers.LoadSytemCACertPool()

	tlsConfig := &tls.Config{}

	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.CACertificateFile != "" {
		cert, err := helpers.ReadCertificateFromFile(cfg.CACertificateFile)
		if err != nil {
			return nil, err
		}

		caPool.AddCert(cert)
	}

	tlsConfig.RootCAs = caPool

	switch cfg.AuthMode {
	case config.MTLS:
		cert, err := tls.LoadX509KeyPair(cfg.AuthMTLSOptions.CertFile, cfg.AuthMTLSOptions.KeyFile)
		if err != nil {
			return nil, err
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

	case config.JWT:
		authHttpCli, err := BuildHTTPClient(config.HTTPClient{
			AuthMode:       config.NoAuth,
			HTTPConnection: cfg.HTTPConnection,
		}, fmt.Sprintf("%s-JWT", clientName))
		if err != nil {
			return nil, err
		}

		type ODICDiscoveryJSON struct {
			Issuer        string `json:"issuer"`
			AuthURL       string `json:"authorization_endpoint"`
			TokenURL      string `json:"token_endpoint"`
			JWKSURL       string `json:"jwks_uri"`
			UserInfoURL   string `json:"userinfo_endpoint"`
			RevocationURL string `json:"revocation_endpoint"`
		}

		wellKnown, err := Get[ODICDiscoveryJSON](context.Background(), authHttpCli, cfg.AuthJWTOptions.OIDCWellKnownURL, &resources.QueryParameters{})
		if err != nil {
			return nil, err
		}

		clientConfig := clientcredentials.Config{
			ClientID:     cfg.AuthJWTOptions.ClientID,
			ClientSecret: cfg.AuthJWTOptions.ClientSecret,
			TokenURL:     fmt.Sprintf(wellKnown.TokenURL),
			// EndpointParams: url.Values{
			// 	"grant_type": {"urn:ietf:params:oauth:grant-type:uma-ticket"},
			// 	"permission": {*resourceProject1.Name + "#scope_read"},
			// 	"audience":   {clientID},
			// },
		}

		authHttpCli.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		httpCtx := context.WithValue(context.Background(), oauth2.HTTPClient, authHttpCli)
		client = clientConfig.Client(httpCtx)
	case config.NoAuth:
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return helpers.BuildHTTPClientWithloggger(client, clientName)
}

func Post[T any](ctx context.Context, client *http.Client, url string, data any) (T, error) {
	var m T
	b, err := toJSON(data)
	if err != nil {
		return m, err
	}
	fmt.Println(string(b))

	byteReader := bytes.NewReader(b)
	r, err := http.NewRequestWithContext(ctx, "POST", url, byteReader)
	if err != nil {
		return m, err
	}
	// Important to set
	r.Header.Add("Content-Type", "application/json")
	res, err := client.Do(r)
	if err != nil {
		return m, err
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return m, err
	}

	if res.StatusCode != 200 && res.StatusCode != 201 {
		return m, fmt.Errorf("unexpected status code %d. Body msg: %s", res.StatusCode, string(body))
	}

	return parseJSON[T](body)
}

func Get[T any](ctx context.Context, client *http.Client, url string, queryParams *resources.QueryParameters) (T, error) {
	var m T

	r, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return m, err
	}

	if queryParams != nil {
		if queryParams.Pagination.NextBookmark != "" {
			query := r.URL.Query()
			query.Add("bookmark", queryParams.Pagination.NextBookmark)
			r.URL.RawQuery = query.Encode()
		}
	}
	// Important to set
	r.Header.Add("Content-Type", "application/json")
	res, err := client.Do(r)
	if err != nil {
		return m, err
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return m, err
	}

	if res.StatusCode != 200 {
		return m, fmt.Errorf("unexpected status code %d. Body msg: %s", res.StatusCode, string(body))
	}

	return parseJSON[T](body)
}

func IterGet[E any, T resources.Iterator[E]](ctx context.Context, client *http.Client, url string, queryParams *resources.QueryParameters, applyFunc func(*E)) error {
	continueIter := true
	if queryParams == nil {
		queryParams = &resources.QueryParameters{}
	}

	queryParams.Pagination.NextBookmark = ""

	for continueIter {
		response, err := Get[T](context.Background(), client, url, queryParams)
		if err != nil {
			return err
		}

		if response.GetNextBookmark() == "" {
			continueIter = false
		} else {
			queryParams.Pagination.NextBookmark = response.GetNextBookmark()
		}

		for _, item := range response.GetList() {
			if item != nil {
				applyFunc(item)
			}
		}
	}

	return nil
}

func parseJSON[T any](s []byte) (T, error) {
	var r T
	if err := json.Unmarshal(s, &r); err != nil {
		return r, err
	}
	return r, nil
}

func toJSON(T any) ([]byte, error) {
	return json.Marshal(T)
}
