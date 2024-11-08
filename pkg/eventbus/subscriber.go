package eventbus

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/services/eventhandling"
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

func NewEventBusSubscriptionHandler(conf cconfig.EventBusEngine, serviceId string, lMessaging *logrus.Entry, handler eventhandling.EventHandler, handlerName string, topic string) (*EventSubscriptionHandler, error) {
	eventBusRouter, err := NewEventBusRouter(conf, serviceId, lMessaging)
	if err != nil {
		return nil, fmt.Errorf("could not setup event bus: %s", err)
	}

	sub, err := NewEventBusSubscriber(conf, serviceId, lMessaging)
	if err != nil {
		lMessaging.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, err
	}

	mHandler := eventBusRouter.AddNoPublisherHandler(handlerName, topic, sub, handler.HandleMessage)

	return &EventSubscriptionHandler{
		router:      eventBusRouter,
		subscriber:  &sub,
		handlerName: handlerName,
		topic:       topic,
		handler:     mHandler,
	}, nil
}

func (s *EventSubscriptionHandler) RunAsync() error {
	errChan := make(chan error)
	go func() {
		err := s.router.Run(context.Background())
		if err != nil {
			errChan <- err
		}

		errChan <- nil
	}()

	select {
	case <-s.router.Running(): // implementation states that when router "running" channel is closed, it means the router is running
		return nil
	case err := <-errChan:
		return err
	}
}

func (s *EventSubscriptionHandler) Stop() {
	s.handler.Stop()
	s.router.Close()
}
