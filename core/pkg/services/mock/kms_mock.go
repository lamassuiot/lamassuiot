package mock

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/mock"
)

type MockKMSService struct {
	mock.Mock
}

// GetCryptoEngineProvider returns available crypto engine providers
func (m *MockKMSService) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.CryptoEngineProvider), args.Error(1)
}

// GetKeyStats returns key statistics with optional filtering
func (m *MockKMSService) GetKeyStats(ctx context.Context, input services.GetKeyStatsInput) (*models.KeyStats, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.KeyStats), args.Error(1)
}

// GetKeys returns a paginated list of keys
func (m *MockKMSService) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	args := m.Called(ctx, input)
	return args.String(0), args.Error(1)
}

// GetKey returns a specific key by identifier (KeyID, Alias, or PKCS11URI)
func (m *MockKMSService) GetKey(ctx context.Context, input services.GetKeyInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

// CreateKey creates a new cryptographic key
func (m *MockKMSService) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

// ImportKey imports an existing private key
func (m *MockKMSService) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

// UpdateKeyMetadata updates the metadata of a key
func (m *MockKMSService) UpdateKeyMetadata(ctx context.Context, input services.UpdateKeyMetadataInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

// UpdateKeyAliases updates the aliases of a key
func (m *MockKMSService) UpdateKeyAliases(ctx context.Context, input services.UpdateKeyAliasesInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

// UpdateKeyName updates the name of a key
func (m *MockKMSService) UpdateKeyName(ctx context.Context, input services.UpdateKeyNameInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

// UpdateKeyTags updates the tags of a key
func (m *MockKMSService) UpdateKeyTags(ctx context.Context, input services.UpdateKeyTagsInput) (*models.Key, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.Key), args.Error(1)
}

// DeleteKeyByID deletes a key by identifier
func (m *MockKMSService) DeleteKeyByID(ctx context.Context, input services.GetKeyInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

// SignMessage signs a message using a key
func (m *MockKMSService) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.MessageSignature), args.Error(1)
}

// VerifySignature verifies a signature against a message
func (m *MockKMSService) VerifySignature(ctx context.Context, input services.VerifySignInput) (*models.MessageValidation, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.MessageValidation), args.Error(1)
}
