package pkg

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/services"
	"github.com/stretchr/testify/mock"
)

type mockAWSCloudConnectorService struct {
	mock.Mock
}

func (m *mockAWSCloudConnectorService) UpdateCertificateStatus(ctx context.Context, input UpdateCertificateStatusInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *mockAWSCloudConnectorService) RegisterAndAttachThing(ctx context.Context, input RegisterAndAttachThingInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *mockAWSCloudConnectorService) UpdateDeviceShadow(ctx context.Context, input UpdateDeviceShadowInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}
func (m *mockAWSCloudConnectorService) RegisterCA(ctx context.Context, input RegisterCAInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}
func (m *mockAWSCloudConnectorService) RegisterGroups(ctx context.Context, input RegisterGroupsInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *mockAWSCloudConnectorService) RegisterUpdatePolicies(ctx context.Context, input RegisterUpdatePoliciesInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *mockAWSCloudConnectorService) RegisterUpdateJITPProvisioner(ctx context.Context, input RegisterUpdateJITPProvisionerInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *mockAWSCloudConnectorService) GetRegisteredCAs(ctx context.Context) ([]*models.CACertificate, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.CACertificate), args.Error(1)
}
func (m *mockAWSCloudConnectorService) GetConnectorID() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockAWSCloudConnectorService) GetDMSService() services.DMSManagerService {
	args := m.Called()
	return args.Get(0).(services.DMSManagerService)
}

func (m *mockAWSCloudConnectorService) GetDeviceService() services.DeviceManagerService {
	args := m.Called()
	return args.Get(0).(services.DeviceManagerService)
}

func (m *mockAWSCloudConnectorService) GetCAService() services.CAService {
	args := m.Called()
	return args.Get(0).(services.CAService)
}

func (m *mockAWSCloudConnectorService) GetRegion() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockAWSCloudConnectorService) GetAccountID() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockAWSCloudConnectorService) GetSQSService() sqs.Client {
	args := m.Called()
	return args.Get(0).(sqs.Client)
}
