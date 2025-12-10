package eventpub

import (
	"context"
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// DMS test configuration
var dmsTestConfig = EventTestConfig[services.DMSManagerService, *svcmock.MockDMSManagerService]{
	NewPublisher: func(pub *CloudEventPublisherMock) func(services.DMSManagerService) services.DMSManagerService {
		return NewDMSEventPublisher(pub)
	},
	CreateMockService: func() *svcmock.MockDMSManagerService {
		return new(svcmock.MockDMSManagerService)
	},
}

// Convenience wrappers for DMS testing
func dmsWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	WithoutErrors(t, dmsTestConfig, method, input, event, expectedOutput, extra...)
}

func dmsWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	WithErrors(t, dmsTestConfig, method, input, event, expectedOutput, extra...)
}

func dmsWithoutErrorsSingleResult[E any](t *testing.T, method string, input E, event models.EventType, extra ...func(*svcmock.MockDMSManagerService)) {
	WithoutErrorsSingleResult(t, dmsTestConfig, method, input, event, extra...)
}

func dmsWithErrorsSingleResult[E any](t *testing.T, method string, input E, event models.EventType, extra ...func(*svcmock.MockDMSManagerService)) {
	WithErrorsSingleResult(t, dmsTestConfig, method, input, event, extra...)
}

// Special wrappers for EST methods that take 3 parameters (ctx, input, aps)
func estWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	expectations := []func(*svcmock.MockDMSManagerService){
		func(mockService *svcmock.MockDMSManagerService) {
			mockService.On(method, mock.Anything, mock.Anything, "").Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(middleware services.DMSManagerService) {
		m := reflect.ValueOf(middleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input), reflect.ValueOf("")})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventPublisherMock, mockService *svcmock.MockDMSManagerService) {
		mockService.AssertExpectations(t)
		mockEventMWPub.AssertExpectations(t)
	}

	GenericEventChecker(dmsTestConfig, event, expectations, operation, assertions)
}

func estWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	expectations := []func(*svcmock.MockDMSManagerService){
		func(mockService *svcmock.MockDMSManagerService) {
			mockService.On(method, mock.Anything, mock.Anything, "").Return(expectedOutput, assert.AnError)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(middleware services.DMSManagerService) {
		m := reflect.ValueOf(middleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input), reflect.ValueOf("")})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventPublisherMock, mockService *svcmock.MockDMSManagerService) {
		mockService.AssertExpectations(t)
		mockEventMWPub.AssertNotCalled(t, "PublishCloudEvent")
	}

	GenericEventChecker(dmsTestConfig, event, expectations, operation, assertions)
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
				dmsWithErrors(t, "UpdateDMS", services.UpdateDMSInput{}, models.EventUpdateDMSKey, &models.DMS{},
					func(mockCAService *svcmock.MockDMSManagerService) {
						mockCAService.On("GetDMSByID", mock.Anything, mock.Anything).Return(&models.DMS{}, nil)
					})
			},
		},
		{
			name: "UpdateDMS without errors - fire event",
			test: func(t *testing.T) {
				dmsWithoutErrors(t, "UpdateDMS", services.UpdateDMSInput{}, models.EventUpdateDMSKey, &models.DMS{},
					func(mockCAService *svcmock.MockDMSManagerService) {
						mockCAService.On("GetDMSByID", mock.Anything, mock.Anything).Return(&models.DMS{}, nil)
					})
			},
		},
		{
			name: "UpdateDMSMetadata with errors - Not fire event",
			test: func(t *testing.T) {
				dmsWithErrors(t, "UpdateDMSMetadata", services.UpdateDMSMetadataInput{}, models.EventUpdateDMSMetadataKey, &models.DMS{},
					func(mockCAService *svcmock.MockDMSManagerService) {
						mockCAService.On("GetDMSByID", mock.Anything, mock.Anything).Return(&models.DMS{}, nil)
					})
			},
		},
		{
			name: "UpdateDMSMetadata without errors - fire event",
			test: func(t *testing.T) {
				dmsWithoutErrors(t, "UpdateDMSMetadata", services.UpdateDMSMetadataInput{}, models.EventUpdateDMSMetadataKey, &models.DMS{},
					func(mockCAService *svcmock.MockDMSManagerService) {
						mockCAService.On("GetDMSByID", mock.Anything, mock.Anything).Return(&models.DMS{}, nil)
					})
			},
		},
		{
			name: "DeleteDMS with errors - Not fire event",
			test: func(t *testing.T) {
				dmsWithErrorsSingleResult(t, "DeleteDMS", services.DeleteDMSInput{}, models.EventDeleteDMSKey)
			},
		},
		{
			name: "DeleteDMS without errors - fire event",
			test: func(t *testing.T) {
				dmsWithoutErrorsSingleResult(t, "DeleteDMS", services.DeleteDMSInput{}, models.EventDeleteDMSKey)
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
