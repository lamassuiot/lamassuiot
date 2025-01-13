package storage

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type MockStorageEngine struct{}

func (m *MockStorageEngine) GetProvider() config.StorageProvider {
	return config.StorageProvider("mockProvider")
}

func (m *MockStorageEngine) GetCAStorage() (CACertificatesRepo, error) {
	return nil, nil
}

func (m *MockStorageEngine) GetCertstorage() (CertificatesRepo, error) {
	return nil, nil
}

func (m *MockStorageEngine) GetCACertificateRequestStorage() (CACertificateRequestRepo, error) {
	return nil, nil
}

func (m *MockStorageEngine) GetDeviceStorage() (DeviceManagerRepo, error) {
	return nil, nil
}

func (m *MockStorageEngine) GetDMSStorage() (DMSRepo, error) {
	return nil, nil
}

func (m *MockStorageEngine) GetEnventsStorage() (EventRepository, error) {
	return nil, nil
}

func (m *MockStorageEngine) GetSubscriptionsStorage() (SubscriptionsRepository, error) {
	return nil, nil
}

func TestRegisterStorageEngine(t *testing.T) {
	mockProvider := config.StorageProvider("mockProvider")
	mockBuilder := func(logger *logrus.Entry, config config.PluggableStorageEngine) (StorageEngine, error) {
		return &MockStorageEngine{}, nil
	}

	RegisterStorageEngine(mockProvider, mockBuilder)

	assert.Contains(t, storageEngineBuilders, mockProvider)
}

func TestGetEngineBuilder(t *testing.T) {
	mockProvider := config.StorageProvider("mockProvider")
	mockBuilder := func(logger *logrus.Entry, config config.PluggableStorageEngine) (StorageEngine, error) {
		return &MockStorageEngine{}, nil
	}

	storageEngineBuilders[mockProvider] = mockBuilder

	builder := GetEngineBuilder(mockProvider)

	assert.NotNil(t, builder)
	engine, err := builder(nil, config.PluggableStorageEngine{})
	assert.NoError(t, err)
	assert.NotNil(t, engine)
	assert.IsType(t, &MockStorageEngine{}, engine)
}
