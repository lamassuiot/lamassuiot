package sdk

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	external_clients "github.com/lamassuiot/lamassuiot/v4/sdk/external"
	"golang.org/x/crypto/ocsp"
)

type VAClient services.VAService

type httpVAClient struct {
	restClient
}

func NewHttpVAClient(client *http.Client, url string) services.VAService {
	return &httpVAClient{
		httpClient: client,
		baseUrl:    url,
	}
}

func (cli *httpVAClient) GetCRL(ctx context.Context, input services.GetCRLResponseInput) (*x509.RevocationList, error) {
	crlURL := cli.baseUrl + "/crl/" + url.PathEscape(input.ID)
	return external_clients.GetCRLResponse(crlURL, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetOCSPResponseGet(ctx context.Context, input services.GetOCSPResponseInput) (*ocsp.Response, error) {
	url := cli.baseUrl + "/ocsp"
	return external_clients.GetOCSPResponseGet(url, input.Certificate, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetOCSPResponsePost(ctx context.Context, input services.GetOCSPResponseInput) (*ocsp.Response, error) {
	url := cli.baseUrl + "/ocsp"
	return external_clients.GetOCSPResponsePost(url, input.Certificate, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetCRLSettingsList(ctx context.Context, input services.GetCRLSettingsListInput) (string, error) {
	path := "/v1/crl-settings"
	return cli.iterGet[models.CRLSettings, *resources.GetItemsResponse[models.CRLSettings]](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpVAClient) GetCRLSettingsByID(ctx context.Context, input services.GetCRLSettingsInput) (*models.CRLSettings, error) {
	path := "/v1/crl-settings/" + url.PathEscape(input.CAID)
	settings, err := cli.get[*models.CRLSettings](ctx, path, nil, map[int][]error{
		404: {errs.ErrCRLSettingsNotFound},
	})
	if err != nil {
		return nil, err
	}

	return settings, nil
}

func (cli *httpVAClient) UpdateCRLSettings(ctx context.Context, input services.UpdateCRLSettingsInput) (*models.CRLSettings, error) {
	response, err := cli.put[*models.CRLSettings](ctx, "/v1/crl-settings/"+url.PathEscape(input.CAID), input.Options, map[int][]error{
		404: {errs.ErrCRLSettingsNotFound, errs.ErrCertificateNotFound},
		400: {errs.ErrValidateBadRequest},
		409: {errs.ErrCRLSettingsNotActive},
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}
