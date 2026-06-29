package inmemory

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
	"github.com/sirupsen/logrus"
)

const fanoutTopic = "__all__" // internal fan-out topic for wildcard subscribers
var wildcardSubscribers int32 // tracks wildcard subscribers to avoid needless fan-out when none

// goChannelPublisher wraps GoChannel publisher to match AMQP/AWS publisher patterns
type goChannelPublisher struct {
	pubsub *gochannel.GoChannel
	logger *logrus.Entry
}

// Publish sends messages to the specified topic and also to a fan-out topic for wildcard subscribers
func (p *goChannelPublisher) Publish(topic string, messages ...*message.Message) error {
	// Add topic to metadata for debugging/tracing
	for _, msg := range messages {
		msg.Metadata.Set("topic", topic)
	}

	// Publish to the original topic
	if err := p.pubsub.Publish(topic, messages...); err != nil {
		return err
	}

	// Also publish copies to a fan-out topic so wildcard subscribers (ca.#, #, etc.) receive them
	if atomic.LoadInt32(&wildcardSubscribers) > 0 {
		fanoutMsgs := make([]*message.Message, 0, len(messages))
		for _, msg := range messages {
			cpy := msg.Copy()
			cpy.Metadata.Set("topic", topic)
			fanoutMsgs = append(fanoutMsgs, cpy)
		}

		return p.pubsub.Publish(fanoutTopic, fanoutMsgs...)
	}

	return nil
}

// Close closes the publisher
func (p *goChannelPublisher) Close() error {
	// GoChannel is closed via the engine
	return nil
}

// goChannelSubscriber wraps GoChannel subscriber to handle topic routing
type goChannelSubscriber struct {
	pubsub    *gochannel.GoChannel
	serviceID string
	logger    *logrus.Entry
}

// Subscribe subscribes to a topic; wildcard patterns are supported via fan-out filtering
func (s *goChannelSubscriber) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	// Wildcard patterns ("#") subscribe to the fan-out topic and filter locally
	if strings.Contains(topic, "#") {
		s.logger.Debugf("subscribing with wildcard: %s (fanout)", topic)
		atomic.AddInt32(&wildcardSubscribers, 1)

		incoming, err := s.pubsub.Subscribe(ctx, fanoutTopic)
		if err != nil {
			s.logger.Errorf("could not subscribe to fanout topic %s: %s", fanoutTopic, err)
			return nil, err
		}

		out := make(chan *message.Message)
		go func() {
			defer close(out)
			for msg := range incoming {
				topicMeta := msg.Metadata.Get("topic")
				if topicMatchesPattern(topic, topicMeta) {
					out <- msg
				} else {
					msg.Ack()
				}
			}
		}()

		return out, nil
	}

	// Exact topic subscription
	s.logger.Debugf("subscribing to topic: %s", topic)

	messages, err := s.pubsub.Subscribe(ctx, topic)
	if err != nil {
		s.logger.Errorf("could not subscribe to topic %s: %s", topic, err)
		return nil, err
	}

	return messages, nil
}

// Close closes the subscriber
func (s *goChannelSubscriber) Close() error {
	// GoChannel is closed via shared singleton
	return nil
}

// topicMatchesPattern matches AMQP-style patterns used by services (e.g., "ca.#", "certificate.#", "#")
func topicMatchesPattern(pattern, actual string) bool {
	if pattern == "#" {
		return true
	}

	if strings.HasSuffix(pattern, "#") {
		prefix := strings.TrimSuffix(pattern, "#")
		return strings.HasPrefix(actual, prefix)
	}

	return pattern == actual
}
