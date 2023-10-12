package clients

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
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

func (cli *dmsManagerClient) CreateDMS(input services.CreateDMSInput) (*models.DMS, error) {
	response, err := Post[*models.DMS](context.Background(), cli.httpClient, cli.baseUrl+"/v1/dms", resources.CreateDMSBody{
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

func (cli *dmsManagerClient) UpdateDMSSettings(input services.UpdateDMSSettingsInput) (*models.DMS, error) {
	response, err := Put[*models.DMS](context.Background(), cli.httpClient, cli.baseUrl+"/v1/dms/"+input.ID+"/settings", input.NewDMSSettings, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *dmsManagerClient) GetDMSByID(input services.GetDMSByIDInput) (*models.DMS, error) {
	url := cli.baseUrl + "/v1/dms/" + input.ID
	resp, err := Get[models.DMS](context.Background(), cli.httpClient, url, nil, map[int][]error{})
	return &resp, err
}

func (cli *dmsManagerClient) GetAll(input services.GetAllInput) (string, error) {
	url := cli.baseUrl + "/v1/dms"

	if input.ExhaustiveRun {
		err := IterGet[models.DMS, *resources.GetDMSsResponse](context.Background(), cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetDMSsResponse](context.Background(), cli.httpClient, url, input.QueryParameters, map[int][]error{})
		return resp.NextBookmark, err
	}
}

func (cli *dmsManagerClient) CACerts(aps string) ([]*x509.Certificate, error) {
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
