package eventbus

import (
	"fmt"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/ThreeDotsLabs/watermill/message/router/plugin"
	"github.com/sirupsen/logrus"
)

func NewMessageRouter(logger *logrus.Entry) (*message.Router, error) {
	lEventBus := NewLoggerAdapter(logger.WithField("subsystem-provider", "EventBus - Router"))

	router, err := message.NewRouter(message.RouterConfig{}, lEventBus)
	if err != nil {
		return nil, fmt.Errorf("could not create event bus router: %s", err)
	}

	router.AddPlugin(plugin.SignalsHandler)
	router.AddMiddleware(
		// CorrelationID will copy the correlation id from the incoming message's metadata to the produced messages
		middleware.CorrelationID,

		// Recoverer handles panics from handlers.
		// In this case, it passes them as errors to the Retry middleware.
		// deadLetterMw,

		// The handler function is retried if it returns an error.
		// After MaxRetries, the message is Nacked and it's up to the PubSub to resend it.
		middleware.Retry{
			MaxRetries:      3,
			InitialInterval: time.Second * 2,
			MaxInterval:     time.Second * 10,
			Multiplier:      3,
			Logger:          lEventBus,
		}.Middleware,

		middleware.Recoverer,
	)

	return router, nil
}
