package sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	hhelpers "github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func BuildURL(cfg config.HTTPClient) string {
	return fmt.Sprintf("%s://%s:%d%s", cfg.Protocol, cfg.Hostname, cfg.Port, cfg.BasePath)
}

func HttpClientWithSourceHeaderInjector(cli *http.Client, sourceID string) *http.Client {
	return HttpClientWithCustomHeaders(cli, models.HttpSourceHeader, sourceID)
}

func HttpClientWithCustomHeaders(cli *http.Client, header string, value string) *http.Client {
	transport := http.DefaultTransport
	if cli.Transport != nil {
		transport = cli.Transport
	}

	cli.Transport = customHeaderRoundTripper{
		transport: transport,
		header:    header,
		value:     value,
	}

	return cli
}

type customHeaderRoundTripper struct {
	transport http.RoundTripper
	header    string
	value     string
}

func (lrt customHeaderRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	req.Header.Add(lrt.header, lrt.value)
	return lrt.transport.RoundTrip(req)
}

func BuildHTTPClient(cfg config.HTTPClient, logger *logrus.Entry) (*http.Client, error) {
	var err error
	client := &http.Client{}
	ctx := chelpers.InitContext()

	caPool := chelpers.LoadSytemCACertPool()

	tlsConfig := &tls.Config{}

	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.CACertificateFile != "" {
		cert, err := chelpers.ReadCertificateFromFile(cfg.CACertificateFile)
		if err != nil {
			return nil, err
		}

		caPool.AddCert(cert)
	}

	tlsConfig.RootCAs = caPool

	switch cfg.AuthMode {
	case config.MTLS:
		var cert tls.Certificate
		//Check If Cert and Key contain a string-like PEM
		if strings.Contains(cfg.AuthMTLSOptions.CertFile, "-----BEGIN CERTIFICATE-----") {
			cert, err = tls.X509KeyPair([]byte(cfg.AuthMTLSOptions.CertFile), []byte(cfg.AuthMTLSOptions.KeyFile))
			if err != nil {
				return nil, err
			}
		} else {
			cert, err = tls.LoadX509KeyPair(cfg.AuthMTLSOptions.CertFile, cfg.AuthMTLSOptions.KeyFile)
			if err != nil {
				return nil, err
			}
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
			TokenURL:     wellKnown.TokenURL,
		}

		authHttpCli.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		httpCtx := context.WithValue(ctx, oauth2.HTTPClient, authHttpCli)
		client = clientConfig.Client(httpCtx)
	case config.ApiKey:
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		client = HttpClientWithCustomHeaders(client, cfg.AuthApiKeyOptions.Header, cfg.AuthApiKeyOptions.Key)

	default:
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return hhelpers.BuildHTTPClientWithTracerLogger(client, logger)
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

	return ParseJSON[T](body)
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

	return ParseJSON[T](body)
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

func IterGet[E any, T resources.Iterator[E]](ctx context.Context, client *http.Client, urlQuery string, exhaustiveRun bool, queryParams *resources.QueryParameters, applyFunc func(E), knownErrors map[int][]error) (string, error) {
	continueIter := true
	if queryParams == nil {
		queryParams = &resources.QueryParameters{}
	}

	if exhaustiveRun {
		queryParams.NextBookmark = ""
	}

	u, err := url.Parse(urlQuery)
	if err != nil {
		return "", fmt.Errorf("could not parse URL %s: %w", urlQuery, err)
	}

	queryParamsValues := encodeQueryParams(u.Query(), queryParams)
	u.RawQuery = queryParamsValues.Encode()
	urlString := u.String()

	for continueIter {
		response, err := Get[T](ctx, client, urlString, queryParams, knownErrors)
		if err != nil {
			return "", err
		}

		if response.GetNextBookmark() == "" || !exhaustiveRun {
			continueIter = false
		}

		queryParams.NextBookmark = response.GetNextBookmark()

		for _, item := range response.GetList() {
			applyFunc(item)
		}
	}

	return queryParams.NextBookmark, nil
}

func ParseJSON[T any](s []byte) (T, error) {
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

	decodedErr, err := ParseJSON[errJson](resBody)
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

func encodeQueryParams(query url.Values, queryParams *resources.QueryParameters) url.Values {
	if queryParams.NextBookmark != "" {
		query.Add("bookmark", queryParams.NextBookmark)
	}

	if queryParams.Sort.SortField != "" {
		query.Add("sort_by", queryParams.Sort.SortField)
	}

	if queryParams.Sort.SortMode != resources.SortModeAsc {
		query.Add("sort_mode", "desc")
	} else {
		query.Add("sort_mode", "asc")
	}

	if queryParams.PageSize > 0 {
		query.Add("page_size", strconv.Itoa(queryParams.PageSize))
	}

	for _, filter := range queryParams.Filters {
		var op string
		switch filter.FilterOperation {
		case resources.StringEqual:
			op = "eq"
		case resources.StringEqualIgnoreCase:
			op = "eq_ic"
		case resources.StringNotEqual:
			op = "ne"
		case resources.StringNotEqualIgnoreCase:
			op = "ne_ic"
		case resources.StringContains:
			op = "ct"
		case resources.StringContainsIgnoreCase:
			op = "ct_ic"
		case resources.StringNotContains:
			op = "nc"
		case resources.StringNotContainsIgnoreCase:
			op = "nc_ic"
		case resources.StringArrayContains:
			op = "ct"
		case resources.StringArrayContainsIgnoreCase:
			op = "ct_ic"
		case resources.DateBefore:
			op = "bf"
		case resources.DateEqual:
			op = "eq"
		case resources.DateAfter:
			op = "af"
		case resources.NumberEqual:
			op = "eq"
		case resources.NumberNotEqual:
			op = "ne"
		case resources.NumberLessThan:
			op = "lt"
		case resources.NumberLessOrEqualThan:
			op = "le"
		case resources.NumberGreaterThan:
			op = "gt"
		case resources.NumberGreaterOrEqualThan:
			op = "ge"
		case resources.EnumEqual:
			op = "eq"
		case resources.EnumNotEqual:
			op = "ne"
		default:
			continue // skip unsupported operations
		}

		query.Add("filter", filter.Field+"["+op+"]"+filter.Value)
	}

	return query
}
