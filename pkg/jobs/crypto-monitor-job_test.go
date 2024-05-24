package jobs

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	svcmock "github.com/lamassuiot/lamassuiot/v2/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUpdateCertificateIfNeededExpiredNoMetadata(t *testing.T) {

	mockService := new(svcmock.MockCAService)

	// Create a new CryptoMonitor instance with the mock service
	cryptoMonitor := NewCryptoMonitor(mockService, nil)

	// Create a sample expired certificate
	certExpired := models.Certificate{
		SerialNumber: "123456",
		ValidTo:      time.Now().AddDate(0, 0, -1), // Expired in 1 day ago,
		Metadata:     map[string]interface{}{},
		Certificate:  &models.X509Certificate{},
	}

	// Set up expectations for UpdateCertificateStatus
	mockService.On("UpdateCertificateStatus", mock.Anything, mock.Anything).Return(&certExpired, nil)

	// Call the function under test
	cryptoMonitor.updateCertificateIfNeeded(certExpired, time.Now(), context.Background())

	// Assert that the expected methods were called
	mockService.AssertCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
	mockService.AssertNotCalled(t, "UpdateCertificateMetadata", mock.Anything, mock.Anything)

	// Create a sample expired certificate
	certValid := models.Certificate{
		SerialNumber: "123456",
		ValidTo:      time.Now().AddDate(0, 0, 1), // Expires in 1 day,
		Metadata:     map[string]interface{}{},
		Certificate:  &models.X509Certificate{},
	}

	cryptoMonitor.updateCertificateIfNeeded(certValid, time.Now(), context.Background())

	// Assert that the expected methods were called
	mockService.AssertCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
	mockService.AssertNotCalled(t, "UpdateCertificateMetadata", mock.Anything, mock.Anything)

}

func TestUpdateCACertificateIfNeededExpiredNoMetadata(t *testing.T) {

	mockService := new(svcmock.MockCAService)

	// Create a new CryptoMonitor instance with the mock service
	cryptoMonitor := NewCryptoMonitor(mockService, nil)

	// Create a sample expired certificate
	certExpired := models.CACertificate{
		ID:       "123456",
		Metadata: map[string]interface{}{},
		Certificate: models.Certificate{
			Status:       models.StatusActive,
			SerialNumber: "123456",
			ValidTo:      time.Now().AddDate(0, 0, -1), // Expired in 1 day ago,
			Metadata:     map[string]interface{}{},
			Certificate:  &models.X509Certificate{},
		},
	}

	// Set up expectations for UpdateCertificateStatus
	mockService.On("UpdateCAStatus", mock.Anything, mock.Anything).Return(&certExpired, nil)

	// Call the function under test
	cryptoMonitor.updateCAIfNeeded(certExpired, time.Now(), context.Background())

	// Assert that the expected methods were called
	mockService.AssertCalled(t, "UpdateCAStatus", mock.Anything, mock.Anything)
	mockService.AssertNotCalled(t, "UpdateCAMetadata", mock.Anything, mock.Anything)

	// Create a sample expired certificate
	certValid := models.CACertificate{
		ID:       "123456",
		Metadata: map[string]interface{}{},
		Certificate: models.Certificate{
			Status:       models.StatusActive,
			SerialNumber: "123456",
			ValidTo:      time.Now().AddDate(0, 0, -1), // Expired in 1 day ago,
			Metadata:     map[string]interface{}{},
			Certificate:  &models.X509Certificate{},
		},
	}

	cryptoMonitor.updateCAIfNeeded(certValid, time.Now(), context.Background())

	// Assert that the expected methods were called
	mockService.AssertCalled(t, "UpdateCAStatus", mock.Anything, mock.Anything)
	mockService.AssertNotCalled(t, "UpdateCAMetadata", mock.Anything, mock.Anything)
}
func TestShouldUpdateMonitoringDeltas(t *testing.T) {
	svc := NewCryptoMonitor(nil, nil)

	// Test case 1: Additional deltas exist and expiration is triggered
	metadata := map[string]interface{}{
		models.CAMetadataMonitoringExpirationDeltasKey: []models.MonitoringExpirationDelta{
			{
				Name:      "Delta1",
				Delta:     models.TimeDuration(24 * time.Hour),
				Triggered: false,
			},
			{
				Name:      "Delta2",
				Delta:     models.TimeDuration(12 * time.Hour),
				Triggered: false,
			},
		},
	}
	certificate := x509.Certificate{
		NotAfter: time.Now().Add(23 * time.Hour),
	}
	shouldUpdate, updatedMetadata := svc.shouldUpdateMonitoringDeltas(metadata, certificate)
	assert.True(t, shouldUpdate)
	// Delta 2 should be triggered
	assert.Equal(t, false, updatedMetadata[models.CAMetadataMonitoringExpirationDeltasKey].(models.CAMetadataMonitoringExpirationDeltas)[0].Triggered)
	// Delta 1 should not be triggered
	assert.Equal(t, true, updatedMetadata[models.CAMetadataMonitoringExpirationDeltasKey].(models.CAMetadataMonitoringExpirationDeltas)[1].Triggered)

	// Test case 2: Additional deltas exist but expiration is not triggered
	metadata = map[string]interface{}{
		models.CAMetadataMonitoringExpirationDeltasKey: []models.MonitoringExpirationDelta{
			{
				Name:      "Delta1",
				Delta:     models.TimeDuration(24 * time.Hour),
				Triggered: false,
			},
			{
				Name:      "Delta2",
				Delta:     models.TimeDuration(48 * time.Hour),
				Triggered: false,
			},
		},
	}
	certificate = x509.Certificate{
		NotAfter: time.Now().Add(49 * time.Hour),
	}
	shouldUpdate, updatedMetadata = svc.shouldUpdateMonitoringDeltas(metadata, certificate)
	assert.False(t, shouldUpdate)
	assert.Empty(t, updatedMetadata)

	// Test case 3: Additional deltas do not exist
	metadata = map[string]interface{}{}
	certificate = x509.Certificate{
		NotAfter: time.Now().Add(-25 * time.Hour),
	}
	shouldUpdate, updatedMetadata = svc.shouldUpdateMonitoringDeltas(metadata, certificate)
	assert.False(t, shouldUpdate)
	assert.Empty(t, updatedMetadata)
}

func TestUpdateCertificateIfNeededExpiredwithMetadata(t *testing.T) {

	mockService := new(svcmock.MockCAService)

	// Create a new CryptoMonitor instance with the mock service
	cryptoMonitor := NewCryptoMonitor(mockService, nil)

	// Create a sample expired certificate
	certExpired := models.Certificate{
		SerialNumber: "123456",
		ValidTo:      time.Now().AddDate(0, 0, 10), // Expired in 1 day ago,
		Metadata: map[string]interface{}{
			models.CAMetadataMonitoringExpirationDeltasKey: []models.MonitoringExpirationDelta{
				{
					Name:      "Delta1",
					Delta:     models.TimeDuration(24 * time.Hour),
					Triggered: false,
				},
			},
		},
		Certificate: &models.X509Certificate{
			NotAfter: time.Now().AddDate(0, 0, -1),
		},
	}

	// Set up expectations for UpdateCertificateStatus
	mockService.On("UpdateCertificateStatus", mock.Anything, mock.Anything).Return(&certExpired, nil)
	mockService.On("UpdateCertificateMetadata", mock.Anything, mock.Anything).Return(&certExpired, nil)

	// Call the function under test
	cryptoMonitor.updateCertificateIfNeeded(certExpired, time.Now(), context.Background())

	// Assert that the expected methods were called
	mockService.AssertNotCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
	mockService.AssertCalled(t, "UpdateCertificateMetadata", mock.Anything, mock.Anything)
}

func TestUpdateCACertificateIfNeededNotExpiredWithMetadata(t *testing.T) {

	mockService := new(svcmock.MockCAService)

	// Create a new CryptoMonitor instance with the mock service
	cryptoMonitor := NewCryptoMonitor(mockService, nil)

	// Create a sample expired certificate
	certExpired := models.CACertificate{
		ID: "123456",
		Metadata: map[string]interface{}{
			models.CAMetadataMonitoringExpirationDeltasKey: []models.MonitoringExpirationDelta{
				{
					Name:      "Delta1",
					Delta:     models.TimeDuration(24 * time.Hour),
					Triggered: false,
				},
			},
		},
		Certificate: models.Certificate{
			Status:       models.StatusActive,
			SerialNumber: "123456",
			ValidTo:      time.Now().AddDate(0, 0, 10), // Expired in 1 day ago,
			Metadata:     map[string]interface{}{},
			Certificate:  &models.X509Certificate{},
		},
	}

	// Set up expectations for UpdateCertificateStatus
	mockService.On("UpdateCAStatus", mock.Anything, mock.Anything).Return(&certExpired, nil)
	mockService.On("UpdateCAMetadata", mock.Anything, mock.Anything).Return(&certExpired, nil)

	// Call the function under test
	cryptoMonitor.updateCAIfNeeded(certExpired, time.Now(), context.Background())

	// Assert that the expected methods were called
	mockService.AssertNotCalled(t, "UpdateCAStatus", mock.Anything, mock.Anything)
	mockService.AssertCalled(t, "UpdateCAMetadata", mock.Anything, mock.Anything)
}
