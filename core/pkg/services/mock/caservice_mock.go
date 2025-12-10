package mock

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/mock"
)

type MockCAService struct {
	mock.Mock
}

func (m *MockCAService) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (*models.Certificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Certificate), args.Error(1)
}
func (m *MockCAService) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (*models.Certificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Certificate), args.Error(1)
}

func (m *MockCAService) DeleteCertificate(ctx context.Context, input services.DeleteCertificateInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *MockCAService) GetStats(ctx context.Context) (*models.CAStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*models.CAStats), args.Error(1)
}

func (m *MockCAService) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(map[models.CertificateStatus]int), args.Error(1)
}

func (m *MockCAService) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.CryptoEngineProvider), args.Error(1)
}

func (m *MockCAService) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}

<<<<<<< HEAD
func (m *MockCAService) CreateHybridCA(ctx context.Context, input services.CreateHybridCAInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}

func (m *MockCAService) RequestCACSR(ctx context.Context, input services.RequestCAInput) (*models.CACertificateRequest, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificateRequest), args.Error(1)
}

=======
>>>>>>> main
func (m *MockCAService) ImportCA(ctx context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}
func (m *MockCAService) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}
func (m *MockCAService) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}
func (m *MockCAService) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)

}
func (m *MockCAService) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}
func (m *MockCAService) UpdateCAProfile(ctx context.Context, input services.UpdateCAProfileInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}
func (m *MockCAService) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)

}
func (m *MockCAService) DeleteCA(ctx context.Context, input services.DeleteCAInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *MockCAService) SignatureSign(ctx context.Context, input services.SignatureSignInput) ([]byte, error) {
	args := m.Called(ctx, input)
	val := args.Get(0).(*[]byte)
	if val != nil {
		return *val, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockCAService) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (bool, error) {
	args := m.Called(ctx, input)
	return args.Bool(0), args.Error(1)
}

func (m *MockCAService) SignCertificate(ctx context.Context, input services.SignCertificateInput) (*models.Certificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Certificate), args.Error(1)
}

func (m *MockCAService) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (*models.Certificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Certificate), args.Error(1)
}
func (m *MockCAService) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (*models.Certificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Certificate), args.Error(1)
}

func (m *MockCAService) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Certificate), args.Error(1)
}
func (m *MockCAService) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}
func (m *MockCAService) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}
func (m *MockCAService) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}
func (m *MockCAService) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}

func (m *MockCAService) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}

func (m *MockCAService) DeleteCARequestByID(ctx context.Context, input services.GetByIDInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

// KMS
func (m *MockCAService) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}

func (m *MockCAService) GetKeyByID(ctx context.Context, input services.GetByIDInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

func (m *MockCAService) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

func (m *MockCAService) DeleteKeyByID(ctx context.Context, input services.GetByIDInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}
func (m *MockCAService) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.MessageSignature), args.Error(1)
}

func (m *MockCAService) VerifySignature(ctx context.Context, input services.VerifySignInput) (*models.MessageValidation, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.MessageValidation), args.Error(1)
}

func (m *MockCAService) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

// Issuance Profiles
func (m *MockCAService) GetIssuanceProfiles(ctx context.Context, input services.GetIssuanceProfilesInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}

func (m *MockCAService) GetIssuanceProfileByID(ctx context.Context, input services.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.IssuanceProfile), args.Error(1)
}

func (m *MockCAService) CreateIssuanceProfile(ctx context.Context, input services.CreateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.IssuanceProfile), args.Error(1)
}

func (m *MockCAService) UpdateIssuanceProfile(ctx context.Context, input services.UpdateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.IssuanceProfile), args.Error(1)
}

func (m *MockCAService) DeleteIssuanceProfile(ctx context.Context, input services.DeleteIssuanceProfileInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}
