package clients

import (
	"context"
	"net/http"

	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type deviceManagerClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewHttpDeviceManagerClient(client *http.Client, url string) services.DeviceManagerService {
	baseURL := url
	return &deviceManagerClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *deviceManagerClient) GetDevicesStats(ctx context.Context, input services.GetDevicesStatsInput) (*models.DevicesStats, error) {
	response, err := Get[models.DevicesStats](ctx, cli.httpClient, cli.baseUrl+"/v1/stats", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *deviceManagerClient) CreateDevice(ctx context.Context, input services.CreateDeviceInput) (*models.Device, error) {
	response, err := Post[*models.Device](ctx, cli.httpClient, cli.baseUrl+"/v1/devices", resources.CreateDeviceBody{
		ID:        input.ID,
		Alias:     input.Alias,
		Tags:      input.Tags,
		Metadata:  input.Metadata,
		DMSID:     input.DMSID,
		Icon:      input.Icon,
		IconColor: input.IconColor,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) GetDeviceByID(ctx context.Context, input services.GetDeviceByIDInput) (*models.Device, error) {
	response, err := Get[models.Device](ctx, cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID, nil, map[int][]error{
		400: {errs.ErrDeviceNotFound},
	})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *deviceManagerClient) GetDevices(ctx context.Context, input services.GetDevicesInput) (string, error) {
	url := cli.baseUrl + "/v1/devices"

	return IterGet[models.Device, *resources.GetDevicesResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}
func (cli *deviceManagerClient) GetDeviceByDMS(ctx context.Context, input services.GetDevicesByDMSInput) (string, error) {
	url := cli.baseUrl + "/v1/devices/dms/" + input.DMSID

	return IterGet[models.Device, *resources.GetDevicesResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})

}

func (cli *deviceManagerClient) UpdateDeviceStatus(ctx context.Context, input services.UpdateDeviceStatusInput) (*models.Device, error) {
	response, err := Post[*models.Device](ctx, cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID+"/decommission", "", map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) UpdateDeviceIdentitySlot(ctx context.Context, input services.UpdateDeviceIdentitySlotInput) (*models.Device, error) {
	response, err := Put[*models.Device](ctx, cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID+"/idslot", resources.UpdateDeviceIdentitySlotBody{
		Slot: input.Slot,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) UpdateDeviceMetadata(ctx context.Context, input services.UpdateDeviceMetadataInput) (*models.Device, error) {
	response, err := Put[*models.Device](ctx, cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID+"/metadata", resources.UpdateDeviceMetadataBody{
		Metadata: input.Metadata,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
