package eventbus

import (
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
	"github.com/sirupsen/logrus"
)

func NewGoChannelPubSub(logger *logrus.Entry) (message.Publisher, message.Subscriber) {
	lEventBus := newWithLogger(logger.WithField("subsystem-provider", "GoChannel - PubSub"))
	pubSub := gochannel.NewGoChannel(gochannel.Config{}, lEventBus)
	return pubSub, pubSub
}
