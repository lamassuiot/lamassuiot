package eventpub

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v2/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func dmsEventChecker(event models.EventType, expectations []func(*svcmock.MockDMSManagerService), operation func(services.DMSManagerService), assertions func(*CloudEventMiddlewarePublisherMock, *svcmock.MockDMSManagerService)) {
	mockDMSManagerService := new(svcmock.MockDMSManagerService)
	mockEventMWPub := new(CloudEventMiddlewarePublisherMock)
	caEventPublisherMw := NewDMSEventPublisher(mockEventMWPub)
	dmsEventPublisher := caEventPublisherMw(mockDMSManagerService)

	for _, expectation := range expectations {
		expectation(mockDMSManagerService)
	}

	mockEventMWPub.On("PublishCloudEvent", context.Background(), event, mock.Anything)
	operation(dmsEventPublisher)

	assertions(mockEventMWPub, mockDMSManagerService)
}

func dmsWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	expectations := []func(*svcmock.MockDMSManagerService){
		func(mockCAService *svcmock.MockDMSManagerService) {
			mockCAService.On(method, context.Background(), mock.Anything).Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.DMSManagerService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockDMSManagerService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertExpectations(t)
	}

	dmsEventChecker(event, expectations, operation, assertions)
}
func dmsWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	expectations := []func(*svcmock.MockDMSManagerService){
		func(mockCAService *svcmock.MockDMSManagerService) {
			mockCAService.On(method, context.Background(), mock.Anything).Return(expectedOutput, errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(deviceMiddleware services.DMSManagerService) {
		m := reflect.ValueOf(deviceMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockDMSManagerService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertNotCalled(t, "PublishCloudEvent")
	}

	dmsEventChecker(event, expectations, operation, assertions)
}

func estWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	expectations := []func(*svcmock.MockDMSManagerService){
		func(mockCAService *svcmock.MockDMSManagerService) {
			mockCAService.On(method, context.Background(), mock.Anything, "").Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.DMSManagerService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input), reflect.ValueOf("")})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockDMSManagerService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertExpectations(t)
	}

	dmsEventChecker(event, expectations, operation, assertions)
}

func estWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	expectations := []func(*svcmock.MockDMSManagerService){
		func(mockCAService *svcmock.MockDMSManagerService) {
			mockCAService.On(method, context.Background(), mock.Anything, "").Return(expectedOutput, errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(deviceMiddleware services.DMSManagerService) {
		m := reflect.ValueOf(deviceMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input), reflect.ValueOf("")})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockDMSManagerService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertNotCalled(t, "PublishCloudEvent")
	}

	dmsEventChecker(event, expectations, operation, assertions)
}

func TestDMSEventPublisher(t *testing.T) {

	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "CreateDMS with errors - Not fire event",
			test: func(t *testing.T) {
				dmsWithErrors(t, "CreateDMS", services.CreateDMSInput{}, models.EventCreateDMSKey, &models.DMS{})
			},
		},
		{
			name: "CreateDMS without errors - fire event",
			test: func(t *testing.T) {
				dmsWithoutErrors(t, "CreateDMS", services.CreateDMSInput{}, models.EventCreateDMSKey, &models.DMS{})
			},
		},
		{
			name: "UpdateDMS with errors - Not fire event",
			test: func(t *testing.T) {
				dmsWithErrors(t, "UpdateDMS", services.UpdateDMSInput{}, models.EventUpdateDMSMetadataKey, &models.DMS{},
					func(mockCAService *svcmock.MockDMSManagerService) {
						mockCAService.On("GetDMSByID", context.Background(), mock.Anything).Return(&models.DMS{}, nil)
					})
			},
		},
		{
			name: "UpdateDMS without errors - fire event",
			test: func(t *testing.T) {
				dmsWithoutErrors(t, "UpdateDMS", services.UpdateDMSInput{}, models.EventUpdateDMSMetadataKey, &models.DMS{},
					func(mockCAService *svcmock.MockDMSManagerService) {
						mockCAService.On("GetDMSByID", context.Background(), mock.Anything).Return(&models.DMS{}, nil)
					})
			},
		},
		{
			name: "Enroll with errors - Not fire event",
			test: func(t *testing.T) {
				estWithErrors(t, "Enroll", &x509.CertificateRequest{}, models.EventEnrollKey, &x509.Certificate{})
			},
		},
		{
			name: "Enroll without errors - fire event",
			test: func(t *testing.T) {
				estWithoutErrors(t, "Enroll", &x509.CertificateRequest{}, models.EventEnrollKey, &x509.Certificate{})
			},
		},
		{
			name: "Reenroll with errors - Not fire event",
			test: func(t *testing.T) {
				estWithErrors(t, "Reenroll", &x509.CertificateRequest{}, models.EventReEnrollKey, &x509.Certificate{})
			},
		},
		{
			name: "Reenroll without errors - fire event",
			test: func(t *testing.T) {
				estWithoutErrors(t, "Reenroll", &x509.CertificateRequest{}, models.EventReEnrollKey, &x509.Certificate{})
			},
		},
		{
			name: "BindIdentityToDevice with errors - Not fire event",
			test: func(t *testing.T) {
				dmsWithErrors(t, "BindIdentityToDevice", services.BindIdentityToDeviceInput{}, models.EventBindDeviceIdentityKey, &models.BindIdentityToDeviceOutput{})
			},
		},
		{
			name: "BindIdentityToDevice without errors - fire event",
			test: func(t *testing.T) {
				dmsWithoutErrors(t, "BindIdentityToDevice", services.BindIdentityToDeviceInput{}, models.EventBindDeviceIdentityKey, &models.BindIdentityToDeviceOutput{})
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
