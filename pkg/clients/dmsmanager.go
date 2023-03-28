package clients

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/globalsign/est"

	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type dmsManagerClient struct {
	httpClient http.Client
	baseUrl    string
	estClient  *est.Client
}

func NewDMSManagerClient(client http.Client, url string, estClient *est.Client) services.DMSManagerService {
	baseURL := url
	return &dmsManagerClient{
		httpClient: client,
		baseUrl:    baseURL,
		estClient:  estClient,
	}
}

func (cli *dmsManagerClient) Create(input services.CreateInput) (*models.DMS, string, error) {
	return nil, "", fmt.Errorf("TODO")
}

func (cli *dmsManagerClient) UpdateStatus(input services.UpdateStatusInput) (*models.DMS, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *dmsManagerClient) UpdateIdentityProfile(input services.UpdateIdentityProfileInput) (*models.DMS, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *dmsManagerClient) GetDMSByID(input services.GetDMSByIDInput) (*models.DMS, error) {
	return nil, fmt.Errorf("TODO")
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
