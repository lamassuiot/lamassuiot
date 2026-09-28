package sdk

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"

	core "github.com/lamassuiot/lamassuiot/core/v3"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	external_clients "github.com/lamassuiot/lamassuiot/sdk/v3/external"
	"golang.org/x/crypto/ocsp"
)

type VAClient services.VAService

type httpVAClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewHttpVAClient(client *http.Client, url string) services.VAService {
	return &httpVAClient{
		httpClient: client,
		baseUrl:    url,
	}
}

// publicEndpoint returns the base of the public CRL/OCSP routes: tenant-scoped
// (/tenants/{tenantId}) when the caller carries a validated tenant context,
// and the legacy default-tenant routes otherwise.
func (cli *httpVAClient) publicEndpoint(ctx context.Context) (string, error) {
	tenantContext, err := core.TenantContextFromContext(ctx)
	if errors.Is(err, core.ErrTenantContextRequired) {
		return cli.baseUrl, nil
	}
	if err != nil {
		return "", err
	}
	if err := tenantContext.Validate(); err != nil {
		return "", err
	}
	return cli.baseUrl + "/tenants/" + url.PathEscape(tenantContext.TenantID), nil
}

func (cli *httpVAClient) administrativeEndpoint(ctx context.Context, path string) (string, error) {
	return tenantAwareEndpoint(ctx, cli.baseUrl, path)
}

func (cli *httpVAClient) GetCRL(ctx context.Context, input services.GetCRLResponseInput) (*x509.RevocationList, error) {
	base, err := cli.publicEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	return external_clients.GetCRLResponse(base+"/crl/"+input.CASubjectKeyID, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetOCSPResponseGet(ctx context.Context, input services.GetOCSPResponseInput) (*ocsp.Response, error) {
	base, err := cli.publicEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	return external_clients.GetOCSPResponseGet(base+"/ocsp", input.Certificate, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetOCSPResponsePost(ctx context.Context, input services.GetOCSPResponseInput) (*ocsp.Response, error) {
	base, err := cli.publicEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	return external_clients.GetOCSPResponsePost(base+"/ocsp", input.Certificate, input.Issuer, nil, input.VerifyResponse)
}

func (cli *httpVAClient) GetVARoles(ctx context.Context, input services.GetVARolesInput) (string, error) {
	url, err := cli.administrativeEndpoint(ctx, "/roles")
	if err != nil {
		return "", err
	}
	return IterGet[models.VARole, *resources.GetItemsResponse[models.VARole]](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpVAClient) GetVARoleByID(ctx context.Context, input services.GetVARoleInput) (*models.VARole, error) {
	url, err := cli.administrativeEndpoint(ctx, "/roles/"+input.CASubjectKeyID)
	if err != nil {
		return nil, err
	}
	role, err := Get[*models.VARole](ctx, cli.httpClient, url, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return role, nil
}

func (cli *httpVAClient) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (*models.VARole, error) {
	url, err := cli.administrativeEndpoint(ctx, "/roles/"+input.CASubjectKeyID)
	if err != nil {
		return nil, err
	}
	response, err := Put[*models.VARole](ctx, cli.httpClient, url, input.CRLRole, map[int][]error{})
	if err != nil {
		return nil, err
	}
	return response, nil
}
