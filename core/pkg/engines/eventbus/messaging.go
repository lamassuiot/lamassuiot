package eventbus

import (
	"fmt"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/ThreeDotsLabs/watermill/message/router/plugin"
	"github.com/sirupsen/logrus"
)

<<<<<<< HEAD
func NewMessageRouter(logger *logrus.Entry, poisonPub message.Publisher) (*message.Router, error) {
=======
func NewMessageRouter(logger *logrus.Entry, dlqPub message.Publisher) (*message.Router, error) {
>>>>>>> main
	lEventBus := NewLoggerAdapter(logger.WithField("subsystem-provider", "EventBus - Router"))

	router, err := message.NewRouter(message.RouterConfig{}, lEventBus)
	if err != nil {
		return nil, fmt.Errorf("could not create event bus router: %s", err)
	}

<<<<<<< HEAD
	posionMw, err := middleware.PoisonQueue(poisonPub, "lamassu-dlq")
=======
	dlqMw, err := middleware.PoisonQueue(dlqPub, "lamassu-dlq")
>>>>>>> main
	if err != nil {
		return nil, fmt.Errorf("could not create poison queue middleware: %s", err)
	}

	router.AddPlugin(plugin.SignalsHandler)

	//mw are applied in order they are added. So the first one is the outermost one (recovery wraps all the others for example)
	router.AddMiddleware(
<<<<<<< HEAD
		middleware.Recoverer,

		// // Poision queue middleware will move messages that have been Nacked more than MaxRetries to a separate topic.
		posionMw,
=======
		// Recoverer handles panics from handlers.
		middleware.Recoverer,

		// Dead letter queue middleware will move messages that have been Nacked more than MaxRetries to a separate topic.
		dlqMw,
>>>>>>> main

		// CorrelationID will copy the correlation id from the incoming message's metadata to the produced messages
		middleware.CorrelationID,

		// The handler function is retried if it returns an error.
		// After MaxRetries, it's up to the PubSub to resend it, mark as ACK or NACK.
		middleware.Retry{
			MaxRetries:      3,
			InitialInterval: time.Second * 2,
			MaxInterval:     time.Second * 10,
			Multiplier:      3,
			Logger:          lEventBus,
		}.Middleware,
	)

	return router, nil
}
