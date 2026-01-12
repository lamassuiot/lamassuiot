package auditpub

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type CloudEventPublisherMock struct {
	mock.Mock
}

func (m *CloudEventPublisherMock) PublishCloudEvent(ctx context.Context, payload interface{}) {
	m.Called(ctx, payload)
}

func auditEventChecker(event models.EventType, expectations []func(*svcmock.MockCAService), operation func(services.CAService), assertions func(*CloudEventPublisherMock, *svcmock.MockCAService)) {
	mockCAService := new(svcmock.MockCAService)
	mockCloudEventPub := new(CloudEventPublisherMock)
	auditPublisher := AuditPublisher{
		ICloudEventPublisher: mockCloudEventPub,
	}
	caAuditPublisherMw := NewCAAuditEventBusPublisher(auditPublisher)
	caAuditPublisher := caAuditPublisherMw(mockCAService)

	for _, expectation := range expectations {
		expectation(mockCAService)
	}

	mockCloudEventPub.On("PublishCloudEvent", mock.Anything, mock.Anything)
	operation(caAuditPublisher)

	assertions(mockCloudEventPub, mockCAService)
}

func auditWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockCAService)) {
	expectations := []func(*svcmock.MockCAService){
		func(mockCAService *svcmock.MockCAService) {
			mockCAService.On(method, mock.Anything, mock.Anything).Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.CAService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockCAService *svcmock.MockCAService) {
		mockCAService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	auditEventChecker(event, expectations, operation, assertions)
}

func auditWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockCAService)) {
	expectations := []func(*svcmock.MockCAService){
		func(mockCAService *svcmock.MockCAService) {
			mockCAService.On(method, mock.Anything, mock.Anything).Return(expectedOutput, errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.CAService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockCAService *svcmock.MockCAService) {
		mockCAService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	auditEventChecker(event, expectations, operation, assertions)
}

func TestCAAuditEventPublisher(t *testing.T) {
	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "CreateCA with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "CreateCA", services.CreateCAInput{}, models.EventCreateCAKey, &models.CACertificate{})
			},
		},
		{
			name: "CreateCA without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "CreateCA", services.CreateCAInput{}, models.EventCreateCAKey, &models.CACertificate{})
			},
		},
		{
			name: "ImportCA with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "ImportCA", services.ImportCAInput{}, models.EventImportCAKey, &models.CACertificate{})
			},
		},
		{
			name: "ImportCA without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "ImportCA", services.ImportCAInput{}, models.EventImportCAKey, &models.CACertificate{})
			},
		},
		{
			name: "UpdateCAStatus with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "UpdateCAStatus", services.UpdateCAStatusInput{}, models.EventUpdateCAStatusKey, &models.CACertificate{})
			},
		},
		{
			name: "UpdateCAStatus without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "UpdateCAStatus", services.UpdateCAStatusInput{}, models.EventUpdateCAStatusKey, &models.CACertificate{})
			},
		},
		{
			name: "UpdateCAProfile with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "UpdateCAProfile", services.UpdateCAProfileInput{}, models.EventUpdateCAProfileKey, &models.CACertificate{})
			},
		},
		{
			name: "UpdateCAProfile without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "UpdateCAProfile", services.UpdateCAProfileInput{}, models.EventUpdateCAProfileKey, &models.CACertificate{})
			},
		},
		{
			name: "UpdateCAMetadata with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "UpdateCAMetadata", services.UpdateCAMetadataInput{}, models.EventUpdateCAMetadataKey, &models.CACertificate{})
			},
		},
		{
			name: "UpdateCAMetadata without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "UpdateCAMetadata", services.UpdateCAMetadataInput{}, models.EventUpdateCAMetadataKey, &models.CACertificate{})
			},
		},
		{
			name: "ReissueCA with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "ReissueCA", services.ReissueCAInput{}, models.EventReissueCAKey, &models.CACertificate{})
			},
		},
		{
			name: "ReissueCA without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "ReissueCA", services.ReissueCAInput{}, models.EventReissueCAKey, &models.CACertificate{})
			},
		},
		{
			name: "SignCertificate with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "SignCertificate", services.SignCertificateInput{}, models.EventSignCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "SignCertificate without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "SignCertificate", services.SignCertificateInput{}, models.EventSignCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "UpdateCertificateStatus with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "UpdateCertificateStatus", services.UpdateCertificateStatusInput{}, models.EventUpdateCertificateStatusKey, &models.Certificate{})
			},
		},
		{
			name: "UpdateCertificateStatus without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "UpdateCertificateStatus", services.UpdateCertificateStatusInput{}, models.EventUpdateCertificateStatusKey, &models.Certificate{})
			},
		},
		{
			name: "UpdateCertificateMetadata with errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithErrors(t, "UpdateCertificateMetadata", services.UpdateCertificateMetadataInput{}, models.EventUpdateCertificateMetadataKey, &models.Certificate{})
			},
		},
		{
			name: "UpdateCertificateMetadata without errors - Audit event produced",
			test: func(t *testing.T) {
				auditWithoutErrors(t, "UpdateCertificateMetadata", services.UpdateCertificateMetadataInput{}, models.EventUpdateCertificateMetadataKey, &models.Certificate{})
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
