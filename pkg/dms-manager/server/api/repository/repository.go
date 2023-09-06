package repository

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

type DeviceManufacturingServiceRepository interface {
	Insert(ctx context.Context, dms api.DeviceManufacturingService) error
	SelectByName(ctx context.Context, name string) (api.DeviceManufacturingService, error)
	SelectAll(ctx context.Context, queryParameters common.QueryParameters) (int, []api.DeviceManufacturingService, error)
	UpdateDMS(ctx context.Context, dms api.DeviceManufacturingService) error
}
