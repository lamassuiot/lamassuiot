package eventbus

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services/handlers"
	"github.com/sirupsen/logrus"
)

type ISubscriptionHandler interface {
	Run()
	Stop()
}

type EventSubscriptionHandler struct {
	router      *message.Router
	subscriber  *message.Subscriber
	handlerName string
	topic       string
	handler     *message.Handler
}

func NewEventBusSubscriptionHandler(conf config.EventBusEngine, serviceId string, lMessaging *logrus.Entry, handler handlers.EventHandler, handlerName string, topic string) (*EventSubscriptionHandler, error) {

	eventBusRouter, err := NewEventBusRouter(conf, serviceId, lMessaging)
	if err != nil {
		return nil, fmt.Errorf("could not setup event bus: %s", err)
	}

	sub, err := NewEventBusSubscriber(conf, serviceId, lMessaging)
	if err != nil {
		lMessaging.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, err
	}

	mHandler := eventBusRouter.AddNoPublisherHandler(handlerName, topic, sub, handler.HandleEvent)

	return &EventSubscriptionHandler{
		router:      eventBusRouter,
		subscriber:  &sub,
		handlerName: handlerName,
		topic:       topic,
		handler:     mHandler,
	}, nil
}

func (s *EventSubscriptionHandler) RunAsync() {
	go s.router.Run(context.Background())
}

func (s *EventSubscriptionHandler) Stop() {
	s.handler.Stop()
	s.router.Close()
}
