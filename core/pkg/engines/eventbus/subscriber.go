package eventbus

import (
	"context"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

type EventSubscriptionHandler struct {
	router      *message.Router
	subscriber  *message.Subscriber
	handlerName string
	handler     *message.Handler
}

func NewEventBusMessageHandler(handlerName string, topic string, sub message.Subscriber, lMessaging *logrus.Entry, handler eventhandling.EventHandler) (*EventSubscriptionHandler, error) {
	router, err := NewMessageRouter(lMessaging)
	if err != nil {
		return nil, err
	}

	mHandler := router.AddNoPublisherHandler(handlerName, topic, sub, handler.HandleMessage)

	return &EventSubscriptionHandler{
		router:      router,
		subscriber:  &sub,
		handlerName: handlerName,
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
