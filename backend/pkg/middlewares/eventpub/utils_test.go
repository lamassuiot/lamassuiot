package eventpub

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type CloudEventPublisherMock struct {
	mock.Mock
}

func (m *CloudEventPublisherMock) PublishCloudEvent(ctx context.Context, payload interface{}) {
	m.Called(ctx, payload)
}

// EventPublisherFactory creates an event publisher middleware for a specific service
type EventPublisherFactory[S any] func(*CloudEventPublisherMock) func(S) S

// EventTestConfig holds the configuration for event testing
type EventTestConfig[S any, M any] struct {
	NewPublisher      EventPublisherFactory[S]
	CreateMockService func() M
}

// GenericEventChecker is a generic event checker that works with any service type
func GenericEventChecker[S any, M any](
	config EventTestConfig[S, M],
	event models.EventType,
	expectations []func(M),
	operation func(S),
	assertions func(*CloudEventPublisherMock, M),
) {
	mockService := config.CreateMockService()
	mockEventMWPub := new(CloudEventPublisherMock)
	eventPublisherMw := config.NewPublisher(mockEventMWPub)

	// Get the wrapped service using reflection
	serviceValue := reflect.ValueOf(mockService)
	wrappedService := eventPublisherMw(serviceValue.Interface().(S))

	for _, expectation := range expectations {
		expectation(mockService)
	}

	mockEventMWPub.On("PublishCloudEvent", mock.Anything, mock.Anything)
	operation(wrappedService)

	assertions(mockEventMWPub, mockService)
}

// WithoutErrors tests a method that returns (result, error) without errors
func WithoutErrors[S any, M any, E any, O any](
	t *testing.T,
	config EventTestConfig[S, M],
	method string,
	input E,
	event models.EventType,
	expectedOutput O,
	extra ...func(M),
) {
	expectations := []func(M){
		func(mockService M) {
			// Use type assertion to get the underlying mock.Mock
			mockPtr := reflect.ValueOf(mockService).Interface()
			if mocker, ok := mockPtr.(interface {
				On(string, ...interface{}) *mock.Call
			}); ok {
				mocker.On(method, mock.Anything, mock.Anything).Return(expectedOutput, nil)
			}
		},
	}
	expectations = append(expectations, extra...)

	operation := func(middleware S) {
		m := reflect.ValueOf(middleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventPublisherMock, mockService M) {
		mockPtr := reflect.ValueOf(mockService).Interface()
		if mocker, ok := mockPtr.(interface{ AssertExpectations(*testing.T) bool }); ok {
			mocker.AssertExpectations(t)
		}
		mockEventMWPub.AssertExpectations(t)
	}

	GenericEventChecker(config, event, expectations, operation, assertions)
}

// WithErrors tests a method that returns (result, error) with errors
func WithErrors[S any, M any, E any, O any](
	t *testing.T,
	config EventTestConfig[S, M],
	method string,
	input E,
	event models.EventType,
	expectedOutput O,
	extra ...func(M),
) {
	expectations := []func(M){
		func(mockService M) {
			// Use type assertion to get the underlying mock.Mock
			mockPtr := reflect.ValueOf(mockService).Interface()
			if mocker, ok := mockPtr.(interface {
				On(string, ...interface{}) *mock.Call
			}); ok {
				mocker.On(method, mock.Anything, mock.Anything).Return(expectedOutput, errors.New("some error"))
			}
		},
	}
	expectations = append(expectations, extra...)

	operation := func(middleware S) {
		m := reflect.ValueOf(middleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventPublisherMock, mockService M) {
		mockPtr := reflect.ValueOf(mockService).Interface()
		if mocker, ok := mockPtr.(interface{ AssertExpectations(*testing.T) bool }); ok {
			mocker.AssertExpectations(t)
		}
		mockEventMWPub.AssertNotCalled(t, "PublishCloudEvent")
	}

	GenericEventChecker(config, event, expectations, operation, assertions)
}

// WithoutErrorsSingleResult tests a method that returns only error without errors
func WithoutErrorsSingleResult[S any, M any, E any](
	t *testing.T,
	config EventTestConfig[S, M],
	method string,
	input E,
	event models.EventType,
	extra ...func(M),
) {
	expectations := []func(M){
		func(mockService M) {
			// Use type assertion to get the underlying mock.Mock
			mockPtr := reflect.ValueOf(mockService).Interface()
			if mocker, ok := mockPtr.(interface {
				On(string, ...interface{}) *mock.Call
			}); ok {
				mocker.On(method, mock.Anything, mock.Anything).Return(nil)
			}
		},
	}
	expectations = append(expectations, extra...)

	operation := func(middleware S) {
		m := reflect.ValueOf(middleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[0].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventPublisherMock, mockService M) {
		mockPtr := reflect.ValueOf(mockService).Interface()
		if mocker, ok := mockPtr.(interface{ AssertExpectations(*testing.T) bool }); ok {
			mocker.AssertExpectations(t)
		}
		mockEventMWPub.AssertExpectations(t)
	}

	GenericEventChecker(config, event, expectations, operation, assertions)
}

// WithErrorsSingleResult tests a method that returns only error with errors
func WithErrorsSingleResult[S any, M any, E any](
	t *testing.T,
	config EventTestConfig[S, M],
	method string,
	input E,
	event models.EventType,
	extra ...func(M),
) {
	expectations := []func(M){
		func(mockService M) {
			// Use type assertion to get the underlying mock.Mock
			mockPtr := reflect.ValueOf(mockService).Interface()
			if mocker, ok := mockPtr.(interface {
				On(string, ...interface{}) *mock.Call
			}); ok {
				mocker.On(method, mock.Anything, mock.Anything).Return(errors.New("some error"))
			}
		},
	}
	expectations = append(expectations, extra...)

	operation := func(middleware S) {
		m := reflect.ValueOf(middleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[0].Interface())
	}

	assertions := func(mockEventMWPub *CloudEventPublisherMock, mockService M) {
		mockPtr := reflect.ValueOf(mockService).Interface()
		if mocker, ok := mockPtr.(interface{ AssertExpectations(*testing.T) bool }); ok {
			mocker.AssertExpectations(t)
		}
		mockEventMWPub.AssertNotCalled(t, "PublishCloudEvent")
	}

	GenericEventChecker(config, event, expectations, operation, assertions)
}
