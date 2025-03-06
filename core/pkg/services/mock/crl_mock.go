package mock

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/mock"
)

type MockVAService struct {
	mock.Mock
}

func (m *MockVAService) GetCARequests(ctx context.Context, input services.GetItemsInput[models.CACertificateRequest]) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}

func (m *MockVAService) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (*x509.RevocationList, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*x509.RevocationList), args.Error(1)
}

func (m *MockVAService) GetCRL(ctx context.Context, input services.GetCRLInput) (*x509.RevocationList, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*x509.RevocationList), args.Error(1)
}

func (m *MockVAService) GetVARole(ctx context.Context, input services.GetVARoleInput) (*models.VARole, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.VARole), args.Error(1)
}

func (m *MockVAService) GetVARoles(ctx context.Context, input services.GetVARolesInput) (string, error) {
	args := m.Called(ctx, input)
	roles := args.Get(0).(*[]*models.VARole)
	for _, role := range *roles {
		input.ApplyFunc(*role)
	}
	return "", args.Error(1)
}

func (m *MockVAService) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (*models.VARole, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.VARole), args.Error(1)
}
