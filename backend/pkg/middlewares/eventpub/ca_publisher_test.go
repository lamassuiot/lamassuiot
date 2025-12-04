package eventpub

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/mock"
)

// CA test configuration
var caTestConfig = EventTestConfig[services.CAService, *svcmock.MockCAService]{
	NewPublisher: func(pub *CloudEventPublisherMock) func(services.CAService) services.CAService {
		return NewCAEventBusPublisher(pub)
	},
	CreateMockService: func() *svcmock.MockCAService {
		return new(svcmock.MockCAService)
	},
}

// Convenience wrappers for CA testing
func caWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockCAService)) {
	WithoutErrors(t, caTestConfig, method, input, event, expectedOutput, extra...)
}

func caWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockCAService)) {
	WithErrors(t, caTestConfig, method, input, event, expectedOutput, extra...)
}

func caWithoutErrorsSingleResult[E any](t *testing.T, method string, input E, event models.EventType, extra ...func(*svcmock.MockCAService)) {
	WithoutErrorsSingleResult(t, caTestConfig, method, input, event, extra...)
}

func caWithErrorsSingleResult[E any](t *testing.T, method string, input E, event models.EventType, extra ...func(*svcmock.MockCAService)) {
	WithErrorsSingleResult(t, caTestConfig, method, input, event, extra...)
}

func TestCAEventPublisher(t *testing.T) {
	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "ImportCA with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "ImportCA", services.ImportCAInput{}, models.EventImportCAKey, &models.CACertificate{})
			},
		},
		{
			name: "ImportCA without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "ImportCA", services.ImportCAInput{}, models.EventImportCAKey, &models.CACertificate{})
			},
		},
		{
			name: "CreateCA with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "CreateCA", services.CreateCAInput{}, models.EventCreateCAKey, &models.CACertificate{})
			},
		},
		{
			name: "CreateCA without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "CreateCA", services.CreateCAInput{}, models.EventCreateCAKey, &models.CACertificate{})
			},
		},
		{
			name: "SingCertificate with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "SignCertificate", services.SignCertificateInput{}, models.EventSignCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "SingCertificate without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "SignCertificate", services.SignCertificateInput{}, models.EventSignCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "CreateCertificate with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "CreateCertificate", services.CreateCertificateInput{}, models.EventCreateCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "CreateCertificate without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "CreateCertificate", services.CreateCertificateInput{}, models.EventCreateCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "ImportCertificate with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "ImportCertificate", services.ImportCertificateInput{}, models.EventImportCACertificateKey, &models.Certificate{})
			},
		},
		{
			name: "ImportCertificate without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "ImportCertificate", services.ImportCertificateInput{}, "ca.certificate.import", &models.Certificate{})
			},
		},
		{
			name: "SignatureSign with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "SignatureSign", services.SignatureSignInput{}, models.EventSignatureSignKey, new([]byte))
			},
		},
		{
			name: "SignatureSign without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "SignatureSign", services.SignatureSignInput{}, models.EventSignatureSignKey, new([]byte))
			},
		},
		{
			name: "UpdateCAStatus with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "UpdateCAStatus", services.UpdateCAStatusInput{}, models.EventUpdateCAStatusKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCAStatus without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "UpdateCAStatus", services.UpdateCAStatusInput{}, models.EventUpdateCAStatusKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCAMetadata with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "UpdateCAMetadata", services.UpdateCAMetadataInput{}, models.EventUpdateCAMetadataKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCAMetadata without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "UpdateCAMetadata", services.UpdateCAMetadataInput{}, models.EventUpdateCAMetadataKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCertificateStatus with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "UpdateCertificateStatus", services.UpdateCertificateStatusInput{}, models.EventUpdateCertificateStatusKey, &models.Certificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCertificateBySerialNumber", mock.Anything, mock.Anything).Return(&models.Certificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCertificateStatus without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "UpdateCertificateStatus", services.UpdateCertificateStatusInput{}, models.EventUpdateCertificateStatusKey, &models.Certificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCertificateBySerialNumber", mock.Anything, mock.Anything).Return(&models.Certificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCertificateMetadata with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "UpdateCertificateMetadata", services.UpdateCertificateMetadataInput{}, models.EventUpdateCertificateMetadataKey, &models.Certificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCertificateBySerialNumber", mock.Anything, mock.Anything).Return(&models.Certificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCertificateMetadata without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "UpdateCertificateMetadata", services.UpdateCertificateMetadataInput{}, models.EventUpdateCertificateMetadataKey, &models.Certificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCertificateBySerialNumber", mock.Anything, mock.Anything).Return(&models.Certificate{}, nil)
					})
			},
		},
		{
			name: "DeleteCA with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrorsSingleResult(t, "DeleteCA", services.DeleteCAInput{}, models.EventDeleteCAKey)
			},
		},
		{
			name: "DeleteCA without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrorsSingleResult(t, "DeleteCA", services.DeleteCAInput{}, models.EventDeleteCAKey)
			},
		},
		{
			name: "DeleteCertificate with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrorsSingleResult(t, "DeleteCertificate", services.DeleteCertificateInput{}, models.EventDeleteCertificateKey)
			},
		},
		{
			name: "DeleteCertificate without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrorsSingleResult(t, "DeleteCertificate", services.DeleteCertificateInput{}, models.EventDeleteCertificateKey)
			},
		},
		{
			name: "UpdateCAProfile with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "UpdateCAProfile", services.UpdateCAProfileInput{}, models.EventUpdateCAProfileKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCAProfile without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "UpdateCAProfile", services.UpdateCAProfileInput{}, models.EventUpdateCAProfileKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "ReissueCA with errors - Not fire event",
			test: func(t *testing.T) {
				caWithErrors(t, "ReissueCA", services.ReissueCAInput{}, models.EventReissueCAKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "ReissueCA without errors - fire event",
			test: func(t *testing.T) {
				caWithoutErrors(t, "ReissueCA", services.ReissueCAInput{}, models.EventReissueCAKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
