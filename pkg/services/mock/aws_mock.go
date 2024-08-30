package mock

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services/iot"
	"github.com/stretchr/testify/mock"
)

type MockAWSCloudConnectorService struct {
	mock.Mock
}

func (m *MockAWSCloudConnectorService) RegisterAndAttachThing(ctx context.Context, input iot.RegisterAndAttachThingInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *MockAWSCloudConnectorService) UpdateDeviceShadow(ctx context.Context, input iot.UpdateDeviceShadowInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}
func (m *MockAWSCloudConnectorService) RegisterCA(ctx context.Context, input iot.RegisterCAInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}
func (m *MockAWSCloudConnectorService) RegisterGroups(ctx context.Context, input iot.RegisterGroupsInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *MockAWSCloudConnectorService) RegisterUpdatePolicies(ctx context.Context, input iot.RegisterUpdatePoliciesInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *MockAWSCloudConnectorService) RegisterUpdateJITPProvisioner(ctx context.Context, input iot.RegisterUpdateJITPProvisionerInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *MockAWSCloudConnectorService) GetRegisteredCAs(ctx context.Context) ([]*models.CACertificate, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.CACertificate), args.Error(1)
}
func (m *MockAWSCloudConnectorService) GetConnectorID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAWSCloudConnectorService) GetDMSService() services.DMSManagerService {
	args := m.Called()
	return args.Get(0).(services.DMSManagerService)
}

func (m *MockAWSCloudConnectorService) GetDeviceService() services.DeviceManagerService {
	args := m.Called()
	return args.Get(0).(services.DeviceManagerService)
}

func (m *MockAWSCloudConnectorService) GetCAService() services.CAService {
	args := m.Called()
	return args.Get(0).(services.CAService)
}

func (m *MockAWSCloudConnectorService) GetRegion() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAWSCloudConnectorService) GetAccountID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAWSCloudConnectorService) GetSQSService() sqs.Client {
	args := m.Called()
	return args.Get(0).(sqs.Client)
}
