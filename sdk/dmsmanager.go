package sdk

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

type dmsManagerClient struct {
	restClient
}

func NewHttpDMSManagerClient(client *http.Client, url string) services.DMSManagerService {
	baseURL := url
	return &dmsManagerClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *dmsManagerClient) GetDMSStats(ctx context.Context, input services.GetDMSStatsInput) (*models.DMSStats, error) {
	path := "/v1/stats"
	resp, err := cli.get[models.DMSStats](ctx, path, input.QueryParameters, map[int][]error{})
	return &resp, err
}

func (cli *dmsManagerClient) CreateDMS(ctx context.Context, input services.CreateDMSInput) (*models.DMS, error) {
	response, err := cli.post[*models.DMS](ctx, "/v1/dms", resources.CreateDMSBody{
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
	response, err := cli.put[*models.DMS](ctx, "/v1/dms/"+input.DMS.ID, input.DMS, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *dmsManagerClient) UpdateDMSMetadata(ctx context.Context, input services.UpdateDMSMetadataInput) (*models.DMS, error) {
	response, err := cli.put[*models.DMS](ctx, "/v1/dms/"+input.ID+"/metadata", resources.UpdateDMSMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *dmsManagerClient) DeleteDMS(ctx context.Context, input services.DeleteDMSInput) error {
	err := cli.delete(ctx, "/v1/dms/"+input.ID, map[int][]error{
		404: {
			errs.ErrDMSNotFound,
		},
		400: {
			errs.ErrValidateBadRequest,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (cli *dmsManagerClient) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	path := "/v1/dms/" + input.ID
	resp, err := cli.get[models.DMS](ctx, path, nil, map[int][]error{})
	return &resp, err
}

func (cli *dmsManagerClient) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	path := "/v1/dms"

	return cli.iterGet[models.DMS, *resources.GetDMSsResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
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

func (cli *dmsManagerClient) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, any, error) {
	return nil, nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error) {
	response, err := cli.post[*models.BindIdentityToDeviceOutput](ctx, "/v1/dms/bind-identity", resources.BindIdentityToDeviceBody{
		BindMode:                input.BindMode,
		DeviceID:                input.DeviceID,
		CertificateSerialNumber: input.CertificateSerialNumber,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
