package clients

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type dmsManagerClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewDMSManagerClient(client *http.Client, url string) services.DMSManagerService {
	baseURL := url
	return &dmsManagerClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *dmsManagerClient) CreateDMS(input services.CreateDMSInput) (*models.DMS, string, error) {
	return nil, "", fmt.Errorf("TODO")
}

func (cli *dmsManagerClient) UpdateStatus(input services.UpdateStatusInput) (*models.DMS, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *dmsManagerClient) UpdateIdentityProfile(input services.UpdateIdentityProfileInput) (*models.DMS, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *dmsManagerClient) GetDMSByID(input services.GetDMSByIDInput) (*models.DMS, error) {
	url := cli.baseUrl + "/v1/dms/" + input.ID
	resp, err := Get[models.DMS](context.Background(), cli.httpClient, url, nil)
	return &resp, err
}

func (cli *dmsManagerClient) GetAll(input services.GetAllInput) (string, error) {
	return "", fmt.Errorf("TODO")
}

func (cli *dmsManagerClient) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) Enroll(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) Reenroll(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) ServerKeyGen(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("not supported, use the estCli instead")
}
