package sdk

import (
	"context"
	"crypto/x509"
	"net/http"

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
	url := cli.baseUrl + "/crl/" + input.CASubjectKeyID
	return external_clients.GetCRLResponse(url, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetOCSPResponseGet(ctx context.Context, input services.GetOCSPResponseInput) (*ocsp.Response, error) {
	url := cli.baseUrl + "/ocsp"
	return external_clients.GetOCSPResponseGet(url, input.Certificate, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetOCSPResponsePost(ctx context.Context, input services.GetOCSPResponseInput) (*ocsp.Response, error) {
	url := cli.baseUrl + "/ocsp"
	return external_clients.GetOCSPResponsePost(url, input.Certificate, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetVARoles(ctx context.Context, input services.GetVARolesInput) (string, error) {
	path := "/roles"
	return cli.iterGet[models.VARole, *resources.GetItemsResponse[models.VARole]](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpVAClient) GetVARoleByID(ctx context.Context, input services.GetVARoleInput) (*models.VARole, error) {
	path := "/roles/" + input.CASubjectKeyID
	role, err := cli.get[*models.VARole](ctx, path, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return role, nil
}

func (cli *httpVAClient) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (*models.VARole, error) {
	response, err := cli.put[*models.VARole](ctx, "/roles/"+input.CASubjectKeyID, input.CRLRole, map[int][]error{})
	if err != nil {
		return nil, err
	}
	return response, nil
}
