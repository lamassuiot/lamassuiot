package eventbus

import (
	"errors"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type mockEventBusEngine struct{}

func (m *mockEventBusEngine) Subscriber() (message.Subscriber, error) {
	return nil, nil
}

func (m *mockEventBusEngine) Publisher() (message.Publisher, error) {
	return nil, nil
}

func mockEventBusBuilder(eventBusProvider string, config interface{}, serviceId string, logger *logrus.Entry) (EventBusEngine, error) {
	if eventBusProvider == "mock" {
		return &mockEventBusEngine{}, nil
	}
	return nil, errors.New("unknown provider")
}

func TestRegisterEventBusEngine(t *testing.T) {
	RegisterEventBusEngine("mock", mockEventBusBuilder)
	assert.NotNil(t, engines["mock"])
}

func TestGetEventBusEngine(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	RegisterEventBusEngine("mock", mockEventBusBuilder)
	RegisterEventBusEngine("error", mockEventBusBuilder)

	engine, err := GetEventBusEngine("mock", nil, "serviceId", logger)
	assert.NoError(t, err)
	assert.NotNil(t, engine)

	engine, err = GetEventBusEngine("unknown", nil, "serviceId", logger)
	assert.NoError(t, err)
	assert.Nil(t, engine)

	engine, err = GetEventBusEngine("error", nil, "serviceId", logger)
	assert.Error(t, err)
	assert.Nil(t, engine)
}
