package mock

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/mock"
)

type MockVAService struct {
	mock.Mock
}

func (m *MockVAService) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (*x509.RevocationList, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*x509.RevocationList), args.Error(1)
}

func (m *MockVAService) GetCRL(ctx context.Context, input services.GetCRLInput) (*x509.RevocationList, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*x509.RevocationList), args.Error(1)
}

func (m *MockVAService) GetCRLSettings(ctx context.Context, input services.GetCRLSettingsInput) (*models.CRLSettings, error) {
	args := m.Called(ctx, input)
	settings, _ := args.Get(0).(*models.CRLSettings)
	return settings, args.Error(1)
}

func (m *MockVAService) GetCRLSettingsList(ctx context.Context, input services.GetCRLSettingsListInput) (string, error) {
	args := m.Called(ctx, input)
	if list, ok := args.Get(0).(*[]*models.CRLSettings); ok {
		for _, settings := range *list {
			input.ApplyFunc(*settings)
		}
	}
	return "", args.Error(1)
}

func (m *MockVAService) UpdateCRLSettings(ctx context.Context, input services.UpdateCRLSettingsInput) (*models.CRLSettings, error) {
	args := m.Called(ctx, input)
	settings, _ := args.Get(0).(*models.CRLSettings)
	return settings, args.Error(1)
}

func (m *MockVAService) InitCRLSettings(ctx context.Context, caID string) (*models.CRLSettings, error) {
	args := m.Called(ctx, caID)
	settings, _ := args.Get(0).(*models.CRLSettings)
	return settings, args.Error(1)
}
