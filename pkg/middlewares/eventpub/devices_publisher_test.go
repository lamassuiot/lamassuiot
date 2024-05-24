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

func devicesEventChecker(event models.EventType, expectations []func(*svcmock.MockDeviceManagerService), operation func(services.DeviceManagerService), assertions func(*CloudEventMiddlewarePublisherMock, *svcmock.MockDeviceManagerService)) {
	mockDeviceManagerService := new(svcmock.MockDeviceManagerService)
	mockEventMWPub := new(CloudEventMiddlewarePublisherMock)
	caEventPublisherMw := NewDeviceEventPublisher(mockEventMWPub)
	caEventPublisher := caEventPublisherMw(mockDeviceManagerService)

	for _, expectation := range expectations {
		expectation(mockDeviceManagerService)
	}

	mockEventMWPub.On("PublishCloudEvent", context.Background(), event, mock.Anything)
	operation(caEventPublisher)

	assertions(mockEventMWPub, mockDeviceManagerService)
}

func devicesWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDeviceManagerService)) {
	expectations := []func(*svcmock.MockDeviceManagerService){
		func(mockCAService *svcmock.MockDeviceManagerService) {
			mockCAService.On(method, context.Background(), mock.Anything).Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(caMiddleware services.DeviceManagerService) {
		m := reflect.ValueOf(caMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockDeviceManagerService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertExpectations(t)
	}

	devicesEventChecker(event, expectations, operation, assertions)
}
func devicesWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDeviceManagerService)) {
	expectations := []func(*svcmock.MockDeviceManagerService){
		func(mockCAService *svcmock.MockDeviceManagerService) {
			mockCAService.On(method, context.Background(), mock.Anything).Return(expectedOutput, errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(deviceMiddleware services.DeviceManagerService) {
		m := reflect.ValueOf(deviceMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventMiddlewarePublisherMock, mockCAService *svcmock.MockDeviceManagerService) {
		mockCAService.AssertExpectations(t)
		mockEventMWPub.AssertNotCalled(t, "PublishCloudEvent")
	}

	devicesEventChecker(event, expectations, operation, assertions)
}

func TestDevicesEventPublisher(t *testing.T) {

	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "CreateDevice with errors - Not fire event",
			test: func(t *testing.T) {
				devicesWithErrors(t, "CreateDevice", services.CreateDeviceInput{}, models.EventCreateDeviceKey, &models.Device{})
			},
		},
		{
			name: "CreateDevice without errors - fire event",
			test: func(t *testing.T) {
				devicesWithoutErrors(t, "CreateDevice", services.CreateDeviceInput{}, models.EventCreateDeviceKey, &models.Device{})
			},
		},
		{
			name: "UpdateDeviceStatus with errors - Not fire event",
			test: func(t *testing.T) {
				devicesWithErrors(t, "UpdateDeviceStatus", services.UpdateDeviceStatusInput{}, models.EventUpdateDeviceStatusKey, &models.Device{},
					func(mockCAService *svcmock.MockDeviceManagerService) {
						mockCAService.On("GetDeviceByID", context.Background(), mock.Anything).Return(&models.Device{}, nil)
					})
			},
		},
		{
			name: "UpdateDeviceStatus without errors - fire event",
			test: func(t *testing.T) {
				devicesWithoutErrors(t, "UpdateDeviceStatus", services.UpdateDeviceStatusInput{}, models.EventUpdateDeviceStatusKey, &models.Device{},
					func(mockCAService *svcmock.MockDeviceManagerService) {
						mockCAService.On("GetDeviceByID", context.Background(), mock.Anything).Return(&models.Device{}, nil)
					})
			},
		},
		{
			name: "UpdateDeviceIdentitySlot with errors - Not fire event",
			test: func(t *testing.T) {
				devicesWithErrors(t, "UpdateDeviceIdentitySlot", services.UpdateDeviceIdentitySlotInput{}, models.EventUpdateDeviceIDSlotKey, &models.Device{},
					func(mockCAService *svcmock.MockDeviceManagerService) {
						mockCAService.On("GetDeviceByID", context.Background(), mock.Anything).Return(&models.Device{}, nil)
					})
			},
		},
		{
			name: "UpdateDeviceIdentitySlot without errors - fire event",
			test: func(t *testing.T) {
				devicesWithoutErrors(t, "UpdateDeviceIdentitySlot", services.UpdateDeviceIdentitySlotInput{}, models.EventUpdateDeviceIDSlotKey, &models.Device{},
					func(mockCAService *svcmock.MockDeviceManagerService) {
						mockCAService.On("GetDeviceByID", context.Background(), mock.Anything).Return(&models.Device{}, nil)
					})
			},
		},
		{
			name: "UpdateDeviceMetadata with errors - Not fire event",
			test: func(t *testing.T) {
				devicesWithErrors(t, "UpdateDeviceMetadata", services.UpdateDeviceMetadataInput{}, models.EventUpdateDeviceMetadataKey, &models.Device{},
					func(mockCAService *svcmock.MockDeviceManagerService) {
						mockCAService.On("GetDeviceByID", context.Background(), mock.Anything).Return(&models.Device{}, nil)
					})
			},
		},
		{
			name: "UpdateDeviceMetadata without errors - fire event",
			test: func(t *testing.T) {
				devicesWithoutErrors(t, "UpdateDeviceMetadata", services.UpdateDeviceMetadataInput{}, models.EventUpdateDeviceMetadataKey, &models.Device{},
					func(mockCAService *svcmock.MockDeviceManagerService) {
						mockCAService.On("GetDeviceByID", context.Background(), mock.Anything).Return(&models.Device{}, nil)
					})
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
