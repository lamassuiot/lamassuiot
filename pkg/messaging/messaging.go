package messaging

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-amqp/v2/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/sirupsen/logrus"
)

type MessagingEngine struct {
	logger     logrus.Entry
	serviceID  string
	publisher  message.Publisher
	Subscriber message.Subscriber
}

func NewMessagingEngine(logger *logrus.Entry, conf config.EventBusEngine, serviceID string) (*MessagingEngine, error) {
	switch conf.Provider {
	case config.Amqp:
		userPassUrlPrefix := ""
		if conf.Amqp.BasicAuth.Enabled {
			logger.Debugf("basic auth enabled")
			userPassUrlPrefix = fmt.Sprintf("%s:%s@", url.PathEscape(conf.Amqp.BasicAuth.Username), url.PathEscape(string(conf.Amqp.BasicAuth.Password)))
		}

		amqpURL := fmt.Sprintf("%s://%s%s:%d", conf.Amqp.Protocol, userPassUrlPrefix, conf.Amqp.Hostname, conf.Amqp.Port)
		logger.Debugf("AMQP Broker URL: %s", amqpURL)

		amqpConfig := amqp.NewDurablePubSubConfig(amqpURL, amqp.GenerateQueueNameTopicNameWithSuffix(serviceID))

		amqpTlsConfig := tls.Config{}
		certPool := helpers.LoadSystemCACertPoolWithExtraCAsFromFiles([]string{conf.Amqp.CACertificateFile})
		amqpTlsConfig.RootCAs = certPool

		if conf.Amqp.InsecureSkipVerify {
			logger.Debugf("tls InsecureSkipVerify set")
			amqpTlsConfig.InsecureSkipVerify = true
		}

		if conf.Amqp.ClientTLSAuth.Enabled {
			logger.Debugf("tls loading mTLS client auth")
			clientTLSCerts, err := tls.LoadX509KeyPair(conf.Amqp.ClientTLSAuth.CertFile, conf.Amqp.ClientTLSAuth.KeyFile)
			if err != nil {
				logger.Errorf("could not load AMQP client TLS certificate or key: %s", err)
				return nil, err
			}

			amqpTlsConfig.Certificates = append(amqpTlsConfig.Certificates, clientTLSCerts)
		}

		amqpConfig.Connection.TLSConfig = &amqpTlsConfig
		// amqpConfig.Exchange = conf.Amqp.Exchange

		subL := newWithLogger(logger.WithField("subsystem-provider", "Subscriber"))
		pubL := newWithLogger(logger.WithField("subsystem-provider", "Publisher"))

		amqpConfig.Exchange = amqp.ExchangeConfig{
			GenerateName: func(topic string) string {
				if conf.Amqp.Exchange != "" {
					return conf.Amqp.Exchange
				} else {
					return "lamassu-events"
				}
			},
			Type:    "topic",
			Durable: true,
		}

		amqpConfig.QueueBind = amqp.QueueBindConfig{
			GenerateRoutingKey: func(topic string) string {
				suf := fmt.Sprintf("_%s", serviceID)
				if strings.Contains(topic, suf) {
					return strings.ReplaceAll(topic, suf, "")
				}
				return topic
			},
		}

		amqpConfig.Publish = amqp.PublishConfig{
			GenerateRoutingKey: func(topic string) string {
				return topic
			},
		}

		subscriber, err := amqp.NewSubscriber(
			// This config is based on this example: https://www.rabbitmq.com/tutorials/tutorial-two-go.html
			// It works as a simple queue.
			//
			// If you want to implement a Pub/Sub style service instead, check
			// https://watermill.io/pubsubs/amqp/#amqp-consumer-groups
			amqpConfig,
			subL,
		)
		if err != nil {
			return nil, fmt.Errorf("could not create subscriber: %s", err)
		}

		publisher, err := amqp.NewPublisher(amqpConfig, pubL)
		if err != nil {
			return nil, fmt.Errorf("could not create publisher: %s", err)
		}

		return &MessagingEngine{
			Subscriber: subscriber,
			publisher:  publisher,
			logger:     *logger,
			serviceID:  serviceID,
		}, nil
	}

	return nil, fmt.Errorf("no implementation exists for provider")
}

type messagingLogger struct {
	entry *logrus.Entry
}

func newWithLogger(l *logrus.Entry) watermill.LoggerAdapter {
	return &messagingLogger{
		entry: l,
	}
}

func (l *messagingLogger) Error(msg string, err error, fields watermill.LogFields) {
	l.entry.WithFields(logrus.Fields(fields)).Error(msg, err)
}

func (l *messagingLogger) Info(msg string, fields watermill.LogFields) {
	l.entry.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *messagingLogger) Debug(msg string, fields watermill.LogFields) {
	l.entry.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *messagingLogger) Trace(msg string, fields watermill.LogFields) {
	l.entry.WithFields(logrus.Fields(fields)).Trace(msg)
}

func (l *messagingLogger) With(fields watermill.LogFields) watermill.LoggerAdapter {
	return &messagingLogger{
		entry: l.entry.WithFields(logrus.Fields(fields)),
	}
}
