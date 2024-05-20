package eventpub

import (
	"context"
	"errors"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type CloudEventMiddlewarePublisherMock struct {
	mock.Mock
}

func (m *CloudEventMiddlewarePublisherMock) PublishCloudEvent(ctx context.Context, eventType models.EventType, payload interface{}) {
	m.Called(ctx, eventType, payload)
}

func TestCAEventPublisherImportCA(t *testing.T) {
	// Create a mock implementation of the CAService interface
	mockCAService := &mockCAService{}

	// Create a mock implementation of the CloudEventMiddlewarePublisher interface
	mockEventMWPub := new(CloudEventMiddlewarePublisherMock)

	// Create a new instance of the CAEventPublisher with the mock dependencies
	caEventPublisherMw := NewCAEventBusPublisher(mockEventMWPub)
	//TODO: Create CAService Mock
	caEventPublisher := caEventPublisherMw(nil)

	// Define the input for the ImportCA function
	input := services.ImportCAInput{
		// Set the necessary fields for the input
	}

	// Define the expected output and error
	expectedOutput := &models.CACertificate{}
	expectedError := errors.New("some error")

	// Set the expectations for the mock CAService's ImportCA function
	mockCAService.On("ImportCA", context.Background(), input).Return(expectedOutput, expectedError)

	// Set the expectations for the mock EventMWPub's PublishCloudEvent function
	mockEventMWPub.On("PublishCloudEvent", context.Background(), models.EventImportCAKey, expectedOutput).Return()

	// Call the ImportCA function on the CAEventPublisher
	output, err := caEventPublisher.ImportCA(context.Background(), input)

	// Assert that the output and error match the expected values
	assert.Equal(t, expectedOutput, output)
	assert.Equal(t, expectedError, err)

	// Assert that the expectations for the mock CAService and mock EventMWPub were met
	mockCAService.AssertExpectations(t)
	mockEventMWPub.AssertExpectations(t)
}

// Define a mock implementation of the CAService interface
type mockCAService struct {
	mock.Mock
}

func (m *mockCAService) ImportCA(ctx context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*models.CACertificate), args.Error(1)
}
