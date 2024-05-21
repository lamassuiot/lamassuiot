package mock

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/stretchr/testify/mock"
)

type MockDMSManagerService struct {
	mock.Mock
}

func (m *MockDMSManagerService) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	args := m.Called(ctx, aps)
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

func (m *MockDMSManagerService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	args := m.Called(ctx, csr, aps)
	return args.Get(0).(*x509.Certificate), args.Get(1), args.Error(2)
}

func (m *MockDMSManagerService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	args := m.Called(ctx, csr, aps)
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockDMSManagerService) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	args := m.Called(ctx, csr, aps)
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockDMSManagerService) GetDMSStats(ctx context.Context, input services.GetDMSStatsInput) (*models.DMSStats, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.DMSStats), args.Error(1)
}

func (m *MockDMSManagerService) CreateDMS(ctx context.Context, input services.CreateDMSInput) (*models.DMS, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.DMS), args.Error(1)
}

func (m *MockDMSManagerService) UpdateDMS(ctx context.Context, input services.UpdateDMSInput) (*models.DMS, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.DMS), args.Error(1)
}

func (m *MockDMSManagerService) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.DMS), args.Error(1)
}

func (m *MockDMSManagerService) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}

func (m *MockDMSManagerService) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.BindIdentityToDeviceOutput), args.Error(1)
}
