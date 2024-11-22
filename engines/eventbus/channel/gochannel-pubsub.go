package channel

import (
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
)

func NewGoChannelPubSub(logger *logrus.Entry) (message.Publisher, message.Subscriber) {
	lEventBus := eventbus.NewLoggerAdapter(logger.WithField("subsystem-provider", "GoChannel - PubSub"))
	pubSub := gochannel.NewGoChannel(gochannel.Config{}, lEventBus)
	return pubSub, pubSub
}
