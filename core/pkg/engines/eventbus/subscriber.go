package eventbus

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

type EventSubscriptionHandler struct {
	router     *message.Router
	subscriber *message.Subscriber
	handlers   []*message.Handler
}

func NewEventBusMessageHandler(service models.ServiceName, topics []string, poisonPub message.Publisher, sub message.Subscriber, lMessaging *logrus.Entry, handler eventhandling.EventHandler) (*EventSubscriptionHandler, error) {
	router, err := NewMessageRouter(lMessaging, poisonPub)
	if err != nil {
		return nil, err
	}

	handlers := []*message.Handler{}
	for _, topic := range topics {
		mHandler := router.AddNoPublisherHandler(fmt.Sprintf("%s-%s", service, topic), topic, sub, handler.HandleMessage)
		handlers = append(handlers, mHandler)
	}

	return &EventSubscriptionHandler{
		router:     router,
		subscriber: &sub,
		handlers:   handlers,
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
	for _, handler := range s.handlers {
		handler.Stop()
	}
	s.router.Close()
}
