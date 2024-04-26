package eventbus

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/ThreeDotsLabs/watermill-amqp/v2/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/sirupsen/logrus"
)

func amqpConfig(conf config.AMQPConnection, serviceID string, logger *logrus.Entry) (*amqp.Config, error) {
	userPassUrlPrefix := ""
	if conf.BasicAuth.Enabled {
		logger.Debugf("basic auth enabled")
		userPassUrlPrefix = fmt.Sprintf("%s:%s@", url.PathEscape(conf.BasicAuth.Username), url.PathEscape(string(conf.BasicAuth.Password)))
	}

	amqpURL := fmt.Sprintf("%s://%s%s:%d", conf.Protocol, userPassUrlPrefix, conf.Hostname, conf.Port)

	amqpConfig := amqp.NewDurablePubSubConfig(amqpURL, amqp.GenerateQueueNameTopicNameWithSuffix(serviceID))

	amqpTlsConfig := tls.Config{}
	certPool := helpers.LoadSystemCACertPoolWithExtraCAsFromFiles([]string{conf.CACertificateFile})
	amqpTlsConfig.RootCAs = certPool

	if conf.InsecureSkipVerify {
		logger.Debugf("tls InsecureSkipVerify set")
		amqpTlsConfig.InsecureSkipVerify = true
	}

	if conf.ClientTLSAuth.Enabled {
		logger.Debugf("tls loading mTLS client auth")
		clientTLSCerts, err := tls.LoadX509KeyPair(conf.ClientTLSAuth.CertFile, conf.ClientTLSAuth.KeyFile)
		if err != nil {
			logger.Errorf("could not load AMQP client TLS certificate or key: %s", err)
			return nil, err
		}

		amqpTlsConfig.Certificates = append(amqpTlsConfig.Certificates, clientTLSCerts)
	}

	amqpConfig.Connection.TLSConfig = &amqpTlsConfig
	amqpConfig.Exchange = amqp.ExchangeConfig{
		GenerateName: func(topic string) string {
			if conf.Exchange != "" {
				return conf.Exchange
			} else {
				return "lamassu-events"
			}
		},
		Type:    "topic",
		Durable: true,
	}

	// amqpConfig.Queue = amqp.QueueConfig{
	// 	GenerateName: func(topic string) string {
	// 		return serviceID
	// 	},
	// 	Durable: true,
	// }

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

	return &amqpConfig, nil
}

func NewAMQPPub(conf config.AMQPConnection, serviceID string, logger *logrus.Entry) (message.Publisher, error) {
	amqpConfig, err := amqpConfig(conf, serviceID, logger)
	if err != nil {
		return nil, err
	}

	lEventBusPub := newWithLogger(logger.WithField("subsystem-provider", "AMQP - Publisher"))

	publisher, err := amqp.NewPublisher(*amqpConfig, lEventBusPub)
	if err != nil {
		return nil, fmt.Errorf("could not create publisher: %s", err)
	}

	return publisher, nil
}

func NewAMQPSub(conf config.AMQPConnection, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {
	amqpConfig, err := amqpConfig(conf, serviceID, logger)
	if err != nil {
		return nil, err
	}

	lEventBusSub := newWithLogger(logger.WithField("subsystem-provider", "AMQP - Subscriber"))
	subscriber, err := amqp.NewSubscriber(
		// This config is based on this example: https://www.rabbitmq.com/tutorials/tutorial-two-go.html
		// It works as a simple queue.
		//
		// If you want to implement a Pub/Sub style service instead, check
		// https://watermill.io/pubsubs/amqp/#amqp-consumer-groups
		*amqpConfig,
		lEventBusSub,
	)
	if err != nil {
		return nil, fmt.Errorf("could not create subscriber: %s", err)
	}

	return subscriber, nil

}
