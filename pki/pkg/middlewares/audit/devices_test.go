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

func deviceAuditEventChecker(event models.EventType, expectations []func(*svcmock.MockDeviceManagerService), operation func(services.DeviceManagerService), assertions func(*CloudEventPublisherMock, *svcmock.MockDeviceManagerService)) {
	mockDeviceService := new(svcmock.MockDeviceManagerService)
	mockCloudEventPub := new(CloudEventPublisherMock)
	auditPublisher := AuditPublisher{
		ICloudEventPublisher: mockCloudEventPub,
	}
	deviceAuditPublisherMw := NewDeviceAuditEventPublisher(auditPublisher)
	deviceAuditPublisher := deviceAuditPublisherMw(mockDeviceService)

	for _, expectation := range expectations {
		expectation(mockDeviceService)
	}

	mockCloudEventPub.On("PublishCloudEvent", mock.Anything, mock.Anything)
	operation(deviceAuditPublisher)

	assertions(mockCloudEventPub, mockDeviceService)
}

func deviceAuditWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDeviceManagerService)) {
	expectations := []func(*svcmock.MockDeviceManagerService){
		func(mockDeviceService *svcmock.MockDeviceManagerService) {
			mockDeviceService.On(method, mock.Anything, mock.Anything).Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(deviceMiddleware services.DeviceManagerService) {
		m := reflect.ValueOf(deviceMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockDeviceService *svcmock.MockDeviceManagerService) {
		mockDeviceService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	deviceAuditEventChecker(event, expectations, operation, assertions)
}

func deviceAuditVoidWithoutErrors(t *testing.T, method string, input interface{}, event models.EventType, extra ...func(*svcmock.MockDeviceManagerService)) {
	expectations := []func(*svcmock.MockDeviceManagerService){
		func(mockDeviceService *svcmock.MockDeviceManagerService) {
			mockDeviceService.On(method, mock.Anything, mock.Anything).Return(nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(deviceMiddleware services.DeviceManagerService) {
		m := reflect.ValueOf(deviceMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[0].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockDeviceService *svcmock.MockDeviceManagerService) {
		mockDeviceService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	deviceAuditEventChecker(event, expectations, operation, assertions)
}

func deviceAuditVoidWithErrors(t *testing.T, method string, input interface{}, event models.EventType, extra ...func(*svcmock.MockDeviceManagerService)) {
	expectations := []func(*svcmock.MockDeviceManagerService){
		func(mockDeviceService *svcmock.MockDeviceManagerService) {
			mockDeviceService.On(method, mock.Anything, mock.Anything).Return(errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(deviceMiddleware services.DeviceManagerService) {
		m := reflect.ValueOf(deviceMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[0].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockDeviceService *svcmock.MockDeviceManagerService) {
		mockDeviceService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	deviceAuditEventChecker(event, expectations, operation, assertions)
}

func deviceAuditWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDeviceManagerService)) {
	expectations := []func(*svcmock.MockDeviceManagerService){
		func(mockDeviceService *svcmock.MockDeviceManagerService) {
			mockDeviceService.On(method, mock.Anything, mock.Anything).Return(expectedOutput, errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(deviceMiddleware services.DeviceManagerService) {
		m := reflect.ValueOf(deviceMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockDeviceService *svcmock.MockDeviceManagerService) {
		mockDeviceService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	deviceAuditEventChecker(event, expectations, operation, assertions)
}

func TestDeviceAuditEventPublisher(t *testing.T) {
	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "CreateDevice with errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditWithErrors(t, "CreateDevice", services.CreateDeviceInput{}, models.EventCreateDeviceKey, &models.Device{})
			},
		},
		{
			name: "CreateDevice without errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditWithoutErrors(t, "CreateDevice", services.CreateDeviceInput{}, models.EventCreateDeviceKey, &models.Device{})
			},
		},
		{
			name: "UpdateDeviceStatus with errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditWithErrors(t, "UpdateDeviceStatus", services.UpdateDeviceStatusInput{}, models.EventUpdateDeviceStatusKey, &models.Device{})
			},
		},
		{
			name: "UpdateDeviceStatus without errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditWithoutErrors(t, "UpdateDeviceStatus", services.UpdateDeviceStatusInput{}, models.EventUpdateDeviceStatusKey, &models.Device{})
			},
		},
		{
			name: "UpdateDeviceIdentitySlot with errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditWithErrors(t, "UpdateDeviceIdentitySlot", services.UpdateDeviceIdentitySlotInput{}, models.EventUpdateDeviceIDSlotKey, &models.Device{})
			},
		},
		{
			name: "UpdateDeviceIdentitySlot without errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditWithoutErrors(t, "UpdateDeviceIdentitySlot", services.UpdateDeviceIdentitySlotInput{}, models.EventUpdateDeviceIDSlotKey, &models.Device{})
			},
		},
		{
			name: "UpdateDeviceMetadata with errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditWithErrors(t, "UpdateDeviceMetadata", services.UpdateDeviceMetadataInput{}, models.EventUpdateDeviceMetadataKey, &models.Device{})
			},
		},
		{
			name: "UpdateDeviceMetadata without errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditWithoutErrors(t, "UpdateDeviceMetadata", services.UpdateDeviceMetadataInput{}, models.EventUpdateDeviceMetadataKey, &models.Device{})
			},
		},
		{
			name: "DeleteDevice with errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditVoidWithErrors(t, "DeleteDevice", services.DeleteDeviceInput{}, models.EventDeleteDeviceKey)
			},
		},
		{
			name: "DeleteDevice without errors - Audit event produced",
			test: func(t *testing.T) {
				deviceAuditVoidWithoutErrors(t, "DeleteDevice", services.DeleteDeviceInput{}, models.EventDeleteDeviceKey)
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
