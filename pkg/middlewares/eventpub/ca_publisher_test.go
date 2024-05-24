package eventpub

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v2/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type CloudEventMiddlewarePublisherMock struct {
	mock.Mock
}

func (m *CloudEventMiddlewarePublisherMock) PublishCloudEvent(ctx context.Context, eventType models.EventType, payload interface{}) {
	m.Called(ctx, eventType, payload)
}

func eventChecker(event models.EventType, expectations []func(*svcmock.MockCAService), operation func(services.CAService), assertions func(*CloudEventMiddlewarePublisherMock, *svcmock.MockCAService)) {
	mockCAService := new(svcmock.MockCAService)
	mockEventMWPub := new(CloudEventMiddlewarePublisherMock)
	caEventPublisherMw := NewCAEventBusPublisher(mockEventMWPub)
	caEventPublisher := caEventPublisherMw(mockCAService)

	for _, expectation := range expectations {
		expectation(mockCAService)
	}

	mockEventMWPub.On("PublishCloudEvent", context.Background(), event, mock.Anything)
	operation(caEventPublisher)

	assertions(mockEventMWPub, mockCAService)
}

func withoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockCAService)) {
	expectations := []func(*svcmock.MockCAService){
		func(mockCAService *svcmock.MockCAService) {
			mockCAService.On(method, context.Background(), mock.Anything).Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.CAService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockCAService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertExpectations(t)
	}

	eventChecker(event, expectations, operation, assertions)
}
func withErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockCAService)) {
	expectations := []func(*svcmock.MockCAService){
		func(mockCAService *svcmock.MockCAService) {
			mockCAService.On(method, context.Background(), mock.Anything).Return(expectedOutput, errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.CAService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockCAService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertNotCalled(t, "PublishCloudEvent")
	}

	eventChecker(event, expectations, operation, assertions)
}

func withoutErrorsSingleResult[E any](t *testing.T, method string, input E, event models.EventType, extra ...func(*svcmock.MockCAService)) {
	expectations := []func(*svcmock.MockCAService){
		func(mockCAService *svcmock.MockCAService) {
			mockCAService.On(method, context.Background(), mock.Anything).Return(nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.CAService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[0].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockCAService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertExpectations(t)
	}

	eventChecker(event, expectations, operation, assertions)
}

func withErrorsSingleResult[E any](t *testing.T, method string, input E, event models.EventType, extra ...func(*svcmock.MockCAService)) {
	expectations := []func(*svcmock.MockCAService){
		func(mockCAService *svcmock.MockCAService) {
			mockCAService.On(method, context.Background(), mock.Anything).Return(errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.CAService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[0].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockCAService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertNotCalled(t, "PublishCloudEvent")
	}

	eventChecker(event, expectations, operation, assertions)
}

func TestCAEventPublisher(t *testing.T) {

	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "ImportCA with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "ImportCA", services.ImportCAInput{}, models.EventImportCAKey, &models.CACertificate{})
			},
		},
		{
			name: "ImportCA without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "ImportCA", services.ImportCAInput{}, models.EventImportCAKey, &models.CACertificate{})
			},
		},
		{
			name: "CreateCA with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "CreateCA", services.CreateCAInput{}, models.EventCreateCAKey, &models.CACertificate{})
			},
		},
		{
			name: "CreateCA without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "CreateCA", services.CreateCAInput{}, models.EventCreateCAKey, &models.CACertificate{})
			},
		},
		{
			name: "SingCertificate with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "SignCertificate", services.SignCertificateInput{}, models.EventSignCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "SingCertificate without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "SignCertificate", services.SignCertificateInput{}, models.EventSignCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "CreateCertificate with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "CreateCertificate", services.CreateCertificateInput{}, models.EventCreateCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "CreateCertificate without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "CreateCertificate", services.CreateCertificateInput{}, models.EventCreateCertificateKey, &models.Certificate{})
			},
		},
		{
			name: "ImportCertificate with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "ImportCertificate", services.ImportCertificateInput{}, models.EventImportCACertificateKey, &models.Certificate{})
			},
		},
		{
			name: "ImportCertificate without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "ImportCertificate", services.ImportCertificateInput{}, "ca.certificate.import", &models.Certificate{})
			},
		},
		{
			name: "SignatureSign with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "SignatureSign", services.SignatureSignInput{}, models.EventSignatureSignKey, new([]byte))
			},
		},
		{
			name: "SignatureSign without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "SignatureSign", services.SignatureSignInput{}, models.EventSignatureSignKey, new([]byte))
			},
		},
		{
			name: "UpdateCAStatus with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "UpdateCAStatus", services.UpdateCAStatusInput{}, models.EventUpdateCAStatusKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", context.Background(), mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCAStatus without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "UpdateCAStatus", services.UpdateCAStatusInput{}, models.EventUpdateCAStatusKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", context.Background(), mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCAMetadata with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "UpdateCAMetadata", services.UpdateCAMetadataInput{}, models.EventUpdateCAMetadataKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", context.Background(), mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCAMetadata without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "UpdateCAMetadata", services.UpdateCAMetadataInput{}, models.EventUpdateCAMetadataKey, &models.CACertificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCAByID", context.Background(), mock.Anything).Return(&models.CACertificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCertificateStatus with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "UpdateCertificateStatus", services.UpdateCertificateStatusInput{}, models.EventUpdateCertificateStatusKey, &models.Certificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCertificateBySerialNumber", context.Background(), mock.Anything).Return(&models.Certificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCertificateStatus without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "UpdateCertificateStatus", services.UpdateCertificateStatusInput{}, models.EventUpdateCertificateStatusKey, &models.Certificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCertificateBySerialNumber", context.Background(), mock.Anything).Return(&models.Certificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCertificateMetadata with errors - Not fire event",
			test: func(t *testing.T) {
				withErrors(t, "UpdateCertificateMetadata", services.UpdateCertificateMetadataInput{}, models.EventUpdateCertificateMetadataKey, &models.Certificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCertificateBySerialNumber", context.Background(), mock.Anything).Return(&models.Certificate{}, nil)
					})
			},
		},
		{
			name: "UpdateCertificateMetadata without errors - fire event",
			test: func(t *testing.T) {
				withoutErrors(t, "UpdateCertificateMetadata", services.UpdateCertificateMetadataInput{}, models.EventUpdateCertificateMetadataKey, &models.Certificate{},
					func(mockCAService *svcmock.MockCAService) {
						mockCAService.On("GetCertificateBySerialNumber", context.Background(), mock.Anything).Return(&models.Certificate{}, nil)
					})
			},
		},
		{
			name: "DeleteCA with errors - Not fire event",
			test: func(t *testing.T) {
				withErrorsSingleResult(t, "DeleteCA", services.DeleteCAInput{}, models.EventDeleteCAKey)
			},
		},
		{
			name: "DeleteCA without errors - fire event",
			test: func(t *testing.T) {
				withoutErrorsSingleResult(t, "DeleteCA", services.DeleteCAInput{}, models.EventDeleteCAKey)
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
