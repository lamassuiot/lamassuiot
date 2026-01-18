package sdk

import (
	"context"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
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
	response, err := Get[models.DevicesStats](ctx, cli.httpClient, cli.baseUrl+"/v1/stats", input.QueryParameters, map[int][]error{})
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
	response, err := DeleteWithBody[*models.Device](ctx, cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID+"/decommission", "", map[int][]error{
		404: {errs.ErrDeviceNotFound},
		422: {errs.ErrDeviceInvalidStatus},
		400: {errs.ErrValidateBadRequest},
	})
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
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) DeleteDevice(ctx context.Context, input services.DeleteDeviceInput) error {
	return Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/devices/"+input.ID, map[int][]error{
		404: {errs.ErrDeviceNotFound},
		422: {errs.ErrDeviceInvalidStatus},
		400: {errs.ErrValidateBadRequest},
	})
}

// ============================================================================
// Device Group Operations
// ============================================================================

func (cli *deviceManagerClient) CreateDeviceGroup(ctx context.Context, input services.CreateDeviceGroupInput) (*models.DeviceGroup, error) {
	response, err := Post[*models.DeviceGroup](ctx, cli.httpClient, cli.baseUrl+"/v1/device-groups", resources.CreateDeviceGroupBody{
		ID:          input.ID,
		Name:        input.Name,
		Description: input.Description,
		ParentID:    input.ParentID,
		Criteria:    convertCriteriaToRequest(input.Criteria),
	}, map[int][]error{
		400: {errs.ErrValidateBadRequest, errs.ErrDeviceGroupCircularReference},
		404: {errs.ErrDeviceGroupNotFound},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) UpdateDeviceGroup(ctx context.Context, input services.UpdateDeviceGroupInput) (*models.DeviceGroup, error) {
	response, err := Put[*models.DeviceGroup](ctx, cli.httpClient, cli.baseUrl+"/v1/device-groups/"+input.ID, resources.UpdateDeviceGroupBody{
		Name:        input.Name,
		Description: input.Description,
		ParentID:    input.ParentID,
		Criteria:    convertCriteriaToRequest(input.Criteria),
	}, map[int][]error{
		400: {errs.ErrValidateBadRequest, errs.ErrDeviceGroupCircularReference},
		404: {errs.ErrDeviceGroupNotFound},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *deviceManagerClient) DeleteDeviceGroup(ctx context.Context, input services.DeleteDeviceGroupInput) error {
	return Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/device-groups/"+input.ID, map[int][]error{
		404: {errs.ErrDeviceGroupNotFound},
		400: {errs.ErrValidateBadRequest},
	})
}

func (cli *deviceManagerClient) GetDeviceGroupByID(ctx context.Context, input services.GetDeviceGroupByIDInput) (*models.DeviceGroup, error) {
	response, err := Get[models.DeviceGroup](ctx, cli.httpClient, cli.baseUrl+"/v1/device-groups/"+input.ID, nil, map[int][]error{
		404: {errs.ErrDeviceGroupNotFound},
	})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *deviceManagerClient) GetDeviceGroups(ctx context.Context, input services.GetDeviceGroupsInput) (string, error) {
	url := cli.baseUrl + "/v1/device-groups"

	return IterGet[models.DeviceGroup, *resources.GetDeviceGroupsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *deviceManagerClient) GetDevicesByGroup(ctx context.Context, input services.GetDevicesByGroupInput) (string, error) {
	url := cli.baseUrl + "/v1/device-groups/" + input.GroupID + "/devices"

	return IterGet[models.Device, *resources.GetDevicesResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{
		404: {errs.ErrDeviceGroupNotFound},
	})
}

func (cli *deviceManagerClient) GetDeviceGroupStats(ctx context.Context, input services.GetDeviceGroupStatsInput) (*models.DevicesStats, error) {
	response, err := Get[models.DevicesStats](ctx, cli.httpClient, cli.baseUrl+"/v1/device-groups/"+input.GroupID+"/stats", nil, map[int][]error{
		404: {errs.ErrDeviceGroupNotFound},
	})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// convertCriteriaToRequest converts model criteria (with FilterOperation integers) to API request criteria (with operand names).
func convertCriteriaToRequest(modelCriteria []models.DeviceGroupFilterOption) []resources.DeviceGroupFilterOptionRequest {
	if len(modelCriteria) == 0 {
		return []resources.DeviceGroupFilterOptionRequest{}
	}

	requestCriteria := make([]resources.DeviceGroupFilterOptionRequest, 0, len(modelCriteria))

	for _, criteria := range modelCriteria {
		// Convert FilterOperation integer back to operand name
		operand := filterOperationToOperandName(resources.FilterOperation(criteria.FilterOperation), resources.DeviceFilterableFields[criteria.Field])

		requestCriteria = append(requestCriteria, resources.DeviceGroupFilterOptionRequest{
			Field:   criteria.Field,
			Operand: operand,
			Value:   criteria.Value,
		})
	}

	return requestCriteria
}

// filterOperationToOperandName converts a FilterOperation enum back to its operand name.
// This is the reverse of ParseOperandName.
func filterOperationToOperandName(filterOp resources.FilterOperation, fieldType resources.FilterFieldType) string {
	switch fieldType {
	case resources.StringFilterFieldType:
		switch filterOp {
		case resources.StringEqual:
			return "eq"
		case resources.StringEqualIgnoreCase:
			return "eq_ic"
		case resources.StringNotEqual:
			return "ne"
		case resources.StringNotEqualIgnoreCase:
			return "ne_ic"
		case resources.StringContains:
			return "ct"
		case resources.StringContainsIgnoreCase:
			return "ct_ic"
		case resources.StringNotContains:
			return "nc"
		case resources.StringNotContainsIgnoreCase:
			return "nc_ic"
		}

	case resources.StringArrayFilterFieldType:
		switch filterOp {
		case resources.StringArrayContains:
			return "contains"
		case resources.StringArrayContainsIgnoreCase:
			return "contains_ignorecase"
		}

	case resources.DateFilterFieldType:
		switch filterOp {
		case resources.DateBefore:
			return "bf"
		case resources.DateEqual:
			return "eq"
		case resources.DateAfter:
			return "af"
		}

	case resources.NumberFilterFieldType:
		switch filterOp {
		case resources.NumberEqual:
			return "eq"
		case resources.NumberNotEqual:
			return "ne"
		case resources.NumberLessThan:
			return "lt"
		case resources.NumberLessOrEqualThan:
			return "le"
		case resources.NumberGreaterThan:
			return "gt"
		case resources.NumberGreaterOrEqualThan:
			return "ge"
		}

	case resources.EnumFilterFieldType:
		switch filterOp {
		case resources.EnumEqual:
			return "eq"
		case resources.EnumNotEqual:
			return "ne"
		}

	case resources.JsonFilterFieldType:
		if filterOp == resources.JsonPathExpression {
			return "jsonpath"
		}
	}

	return "unknown"
}
