package sdk

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type dmsManagerClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewHttpDMSManagerClient(client *http.Client, url string) services.DMSManagerService {
	baseURL := url
	return &dmsManagerClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *dmsManagerClient) GetDMSStats(ctx context.Context, input services.GetDMSStatsInput) (*models.DMSStats, error) {
	url := cli.baseUrl + "/v1/stats"
	resp, err := Get[models.DMSStats](ctx, cli.httpClient, url, nil, map[int][]error{})
	return &resp, err
}

func (cli *dmsManagerClient) CreateDMS(ctx context.Context, input services.CreateDMSInput) (*models.DMS, error) {
	response, err := Post[*models.DMS](ctx, cli.httpClient, cli.baseUrl+"/v1/dms", resources.CreateDMSBody{
		ID:       input.ID,
		Name:     input.Name,
		Metadata: input.Metadata,
		Settings: input.Settings,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *dmsManagerClient) UpdateDMS(ctx context.Context, input services.UpdateDMSInput) (*models.DMS, error) {
	response, err := Put[*models.DMS](ctx, cli.httpClient, cli.baseUrl+"/v1/dms/"+input.DMS.ID, input.DMS, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *dmsManagerClient) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	url := cli.baseUrl + "/v1/dms/" + input.ID
	resp, err := Get[models.DMS](ctx, cli.httpClient, url, nil, map[int][]error{})
	return &resp, err
}

func (cli *dmsManagerClient) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	url := cli.baseUrl + "/v1/dms"

	return IterGet[models.DMS, *resources.GetDMSsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *dmsManagerClient) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error) {
	response, err := Post[*models.BindIdentityToDeviceOutput](ctx, cli.httpClient, cli.baseUrl+"/v1/dms/bind-identity", resources.BindIdentityToDeviceBody{
		BindMode:                input.BindMode,
		DeviceID:                input.DeviceID,
		CertificateSerialNumber: input.CertificateSerialNumber,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
