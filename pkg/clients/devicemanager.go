package clients

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type deviceManagerClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewDeviceManagerClient(client *http.Client, url string) services.DeviceManagerService {
	baseURL := url
	return &deviceManagerClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *deviceManagerClient) CreateDevice(input services.CreateDeviceInput) (*models.Device, error) {
	response, err := Post[*models.Device](context.Background(), cli.httpClient, cli.baseUrl+"/v1/devices", resources.CreateDeviceBody{
		ID:                 input.ID,
		Alias:              input.Alias,
		Tags:               input.Tags,
		ConnectionMetadata: input.ConnectionMetadata,
		Metadata:           input.Metadata,
		DMSID:              input.DMSID,
		Icon:               input.Icon,
		IconColor:          input.IconColor,
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) DecommisionDevice(input services.DecommisionDeviceInput) (*models.Device, error) {
	response, err := Post[*models.Device](context.Background(), cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID+"/decommission", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) GetDeviceByID(input services.GetDeviceByIDInput) (*models.Device, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *deviceManagerClient) GetDevices(input services.GetDevicesInput) (string, error) {
	return "", fmt.Errorf("TODO")
}

func (cli *deviceManagerClient) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *deviceManagerClient) Enroll(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *deviceManagerClient) Reenroll(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *deviceManagerClient) ServerKeyGen(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("not supported, use the estCli instead")
}
