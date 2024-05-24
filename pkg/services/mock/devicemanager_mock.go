package mock

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/stretchr/testify/mock"
)

type MockDeviceManagerService struct {
	mock.Mock
}

func (dm *MockDeviceManagerService) GetDevicesStats(ctx context.Context, input services.GetDevicesStatsInput) (*models.DevicesStats, error) {
	args := dm.Called(ctx, input)
	return args.Get(0).(*models.DevicesStats), args.Error(1)
}

func (dm *MockDeviceManagerService) CreateDevice(ctx context.Context, input services.CreateDeviceInput) (*models.Device, error) {
	args := dm.Called(ctx, input)
	return args.Get(0).(*models.Device), args.Error(1)
}

func (dm *MockDeviceManagerService) GetDeviceByID(ctx context.Context, input services.GetDeviceByIDInput) (*models.Device, error) {
	args := dm.Called(ctx, input)
	return args.Get(0).(*models.Device), args.Error(1)
}

func (dm *MockDeviceManagerService) GetDevices(ctx context.Context, input services.GetDevicesInput) (string, error) {
	args := dm.Called(ctx, input)
	return args.String(0), args.Error(1)
}

func (dm *MockDeviceManagerService) GetDeviceByDMS(ctx context.Context, input services.GetDevicesByDMSInput) (string, error) {
	args := dm.Called(ctx, input)
	return args.String(0), args.Error(1)
}

func (dm *MockDeviceManagerService) UpdateDeviceStatus(ctx context.Context, input services.UpdateDeviceStatusInput) (*models.Device, error) {
	args := dm.Called(ctx, input)
	return args.Get(0).(*models.Device), args.Error(1)
}

func (dm *MockDeviceManagerService) UpdateDeviceIdentitySlot(ctx context.Context, input services.UpdateDeviceIdentitySlotInput) (*models.Device, error) {
	args := dm.Called(ctx, input)
	return args.Get(0).(*models.Device), args.Error(1)
}

func (dm *MockDeviceManagerService) UpdateDeviceMetadata(ctx context.Context, input services.UpdateDeviceMetadataInput) (*models.Device, error) {
	args := dm.Called(ctx, input)
	return args.Get(0).(*models.Device), args.Error(1)
}
