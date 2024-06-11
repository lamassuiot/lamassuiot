package clients

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func BuildURL(cfg config.HTTPClient) string {
	return fmt.Sprintf("%s://%s:%d%s", cfg.Protocol, cfg.Hostname, cfg.Port, cfg.BasePath)
}

func HttpClientWithSourceHeaderInjector(cli *http.Client, sourceID string) *http.Client {
	transport := http.DefaultTransport
	if cli.Transport != nil {
		transport = cli.Transport
	}

	cli.Transport = sourceRoundTripper{
		transport: transport,
		source:    sourceID,
	}

	return cli
}

type sourceRoundTripper struct {
	transport http.RoundTripper
	source    string
}

func (lrt sourceRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	req.Header.Add(models.HttpSourceHeader, lrt.source)
	return lrt.transport.RoundTrip(req)
}

func BuildHTTPClient(cfg config.HTTPClient, logger *logrus.Entry) (*http.Client, error) {
	client := &http.Client{}
	ctx := helpers.InitContext()

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
		}, logger)
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

		wellKnown, err := Get[ODICDiscoveryJSON](ctx, authHttpCli, cfg.AuthJWTOptions.OIDCWellKnownURL, &resources.QueryParameters{}, map[int][]error{})
		if err != nil {
			return nil, err
		}

		clientConfig := clientcredentials.Config{
			ClientID:     cfg.AuthJWTOptions.ClientID,
			ClientSecret: string(cfg.AuthJWTOptions.ClientSecret),
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

		httpCtx := context.WithValue(ctx, oauth2.HTTPClient, authHttpCli)
		client = clientConfig.Client(httpCtx)
	default:
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return helpers.BuildHTTPClientWithTracerLogger(client, logger)
}

func Post[T any](ctx context.Context, client *http.Client, url string, data any, knownErrors map[int][]error) (T, error) {
	return requestWithBody[T](ctx, client, "POST", url, data, knownErrors)
}

func Put[T any](ctx context.Context, client *http.Client, url string, data any, knownErrors map[int][]error) (T, error) {
	return requestWithBody[T](ctx, client, "PUT", url, data, knownErrors)
}

func requestWithBody[T any](ctx context.Context, client *http.Client, method string, url string, data any, knownErrors map[int][]error) (T, error) {
	var m T
	b, err := toJSON(data)
	if err != nil {
		return m, err
	}

	byteReader := bytes.NewReader(b)
	r, err := http.NewRequestWithContext(ctx, method, url, byteReader)
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
		return m, nonOKResponseToError(res.StatusCode, body, knownErrors)
	}

	return parseJSON[T](body)
}

func Get[T any](ctx context.Context, client *http.Client, url string, queryParams *resources.QueryParameters, knownErrors map[int][]error) (T, error) {
	var m T
	r, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return m, err
	}

	if queryParams != nil {
		query := r.URL.Query()
		if queryParams.NextBookmark != "" {
			query.Add("bookmark", queryParams.NextBookmark)
		}

		if queryParams.PageSize > 0 {
			query.Add("page_size", fmt.Sprintf("%d", queryParams.PageSize))
		}

		r.URL.RawQuery = query.Encode()
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
		return m, nonOKResponseToError(res.StatusCode, body, knownErrors)
	}

	return parseJSON[T](body)
}

func Delete(ctx context.Context, client *http.Client, url string, knownErrors map[int][]error) error {
	r, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

	// Important to set
	r.Header.Add("Content-Type", "application/json")
	res, err := client.Do(r)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return nonOKResponseToError(res.StatusCode, body, knownErrors)
	}

	return nil
}

func IterGet[E any, T resources.Iterator[E]](ctx context.Context, client *http.Client, url string, queryParams *resources.QueryParameters, applyFunc func(E), knownErrors map[int][]error) error {
	continueIter := true
	if queryParams == nil {
		queryParams = &resources.QueryParameters{}
	}

	queryParams.NextBookmark = ""

	for continueIter {
		response, err := Get[T](ctx, client, url, queryParams, knownErrors)
		if err != nil {
			return err
		}

		if response.GetNextBookmark() == "" {
			continueIter = false
		} else {
			queryParams.NextBookmark = response.GetNextBookmark()
		}

		for _, item := range response.GetList() {
			if &item != nil {
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

func nonOKResponseToError(resStatusCode int, resBody []byte, knownErrors map[int][]error) error {
	type errJson struct {
		Err string `json:"err"`
	}

	decodedErr, err := parseJSON[errJson](resBody)
	if err != nil {
		return fmt.Errorf("unexpected status code %d. Body err msg could not be decoded: %s", resStatusCode, string(resBody))
	}

	errsInStatusCode := knownErrors[resStatusCode]
	for _, errInSC := range errsInStatusCode {
		if errInSC.Error() == decodedErr.Err {
			return errInSC
		}
	}

	return fmt.Errorf("unexpected status code %d. No expected error matching found: %s", resStatusCode, string(resBody))
}
