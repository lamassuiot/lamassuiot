package clients

import (
	"context"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
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

func (cli *deviceManagerClient) CreateDevice(input services.CreateDeviceInput) (*models.Device, error) {
	response, err := Post[*models.Device](context.Background(), cli.httpClient, cli.baseUrl+"/v1/devices", resources.CreateDeviceBody{
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

func (cli *deviceManagerClient) GetDeviceByID(input services.GetDeviceByIDInput) (*models.Device, error) {
	response, err := Get[models.Device](context.Background(), cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID, nil, map[int][]error{
		400: {errs.ErrDeviceNotFound},
	})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *deviceManagerClient) GetDevices(input services.GetDevicesInput) (string, error) {
	url := cli.baseUrl + "/v1/devices"

	if input.ExhaustiveRun {
		err := IterGet[models.Device, *resources.GetDevicesResponse](context.Background(), cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetDevicesResponse](context.Background(), cli.httpClient, url, input.QueryParameters, map[int][]error{})
		return resp.NextBookmark, err
	}
}
func (cli *deviceManagerClient) GetDeviceByDMS(input services.GetDevicesByDMSInput) (string, error) {
	url := cli.baseUrl + "/v1/devices/dms/" + input.DMSID

	if input.ExhaustiveRun {
		err := IterGet[models.Device, *resources.GetDevicesResponse](context.Background(), cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetDevicesResponse](context.Background(), cli.httpClient, url, input.QueryParameters, map[int][]error{})
		return resp.NextBookmark, err
	}
}

func (cli *deviceManagerClient) UpdateDeviceStatus(input services.UpdateDeviceStatusInput) (*models.Device, error) {
	response, err := Post[*models.Device](context.Background(), cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID+"/decommission", "", map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) UpdateDeviceIdentitySlot(input services.UpdateDeviceIdentitySlotInput) (*models.Device, error) {
	response, err := Put[*models.Device](context.Background(), cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID+"/idslot", resources.UpdateIdentitySlotBody{
		Slot: input.Slot,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) UpdateDeviceMetadata(input services.UpdateDeviceMetadataInput) (*models.Device, error) {
	response, err := Put[*models.Device](context.Background(), cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID+"/metadata", resources.UpdateDeviceMetadataBody{
		Metadata: input.Metadata,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
