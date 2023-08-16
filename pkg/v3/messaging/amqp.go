package messaging

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/sirupsen/logrus"
	"github.com/streadway/amqp"
)

var Exchange = "lamassu-events"
var log *logrus.Entry

type AmqpPublishMessage struct {
	RoutingKey string
	Mandatory  bool
	Immediate  bool
	Msg        amqp.Publishing
}

func SetupAMQPConnection(logger *logrus.Entry, config config.AMQPConnection) (*amqp.Connection, *amqp.Channel, error) {
	log = logger
	amqpCloseChan := make(chan *amqp.Error) //error channel

	var connection *amqp.Connection
	var channel *amqp.Channel

	connection, channel, err := buildAMQPConnection(config)
	if err != nil {
		return nil, nil, err
	}

	connection.NotifyClose(amqpCloseChan)

	go func() {
		for {
			select { //check connection
			case err = <-amqpCloseChan:
				//work with error
				log.Errorf("disconnected from AMQP: %s", err)
				for {
					connection, channel, err = buildAMQPConnection(config)
					connection.NotifyClose(amqpCloseChan)

					if err != nil {
						log.Errorf("failed to reconnect. Sleeping for 5 secodns: %s", err)
						time.Sleep(5 * time.Second)
					} else {
						break
					}
				}
				log.Info("AMQP reconnection success")
			}
		}
	}()

	return connection, channel, nil
}

func buildAMQPConnection(cfg config.AMQPConnection) (*amqp.Connection, *amqp.Channel, error) {
	userPassUrlPrefix := ""
	if cfg.BasicAuth.Enabled {
		log.Debugf("basic auth enabled")
		userPassUrlPrefix = fmt.Sprintf("%s:%s@", url.PathEscape(cfg.BasicAuth.Username), url.PathEscape(cfg.BasicAuth.Password))
	}

	amqpTlsConfig := tls.Config{}
	certPool := helpers.LoadSytemCACertPoolWithExtraCAsFromFiles([]string{cfg.CACertificateFile})
	amqpTlsConfig.RootCAs = certPool

	if cfg.InsecureSkipVerify {
		log.Debugf("tls InsecureSkipVerify set")
		amqpTlsConfig.InsecureSkipVerify = true
	}

	if cfg.ClientTLSAuth.Enabled {
		log.Debugf("tls loading mTLS client auth")
		clientTLSCerts, err := tls.LoadX509KeyPair(cfg.ClientTLSAuth.CertFile, cfg.ClientTLSAuth.KeyFile)
		if err != nil {
			log.Error("could not load AMQP client TLS certificate or key: ", err)
			return nil, nil, err
		}

		amqpTlsConfig.Certificates = append(amqpTlsConfig.Certificates, clientTLSCerts)
	}

	amqpURL := fmt.Sprintf("%s://%s%s:%d", cfg.Protocol, userPassUrlPrefix, cfg.Hostname, cfg.Port)
	log.Debug(amqpURL)
	amqpConn, err := amqp.DialTLS(amqpURL, &amqpTlsConfig)
	if err != nil {
		log.Error("failed to connect to AMQP broker: ", err)
		return nil, nil, err
	}

	amqpChannel, err := amqpConn.Channel()
	if err != nil {
		log.Errorf("could not create AMQP channel: %s", err)
		return nil, nil, err
	}
	log.Debugf("channel created")

	err = amqpChannel.ExchangeDeclare(
		Exchange, // name
		"topic",  // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	if err != nil {
		log.Errorf("could not create AMQP exchange: %s", err)
		return nil, nil, err
	}

	log.Debugf("exchange created")
	return amqpConn, amqpChannel, nil

}

type AMQPEventPublisher struct {
	channel       *amqp.Channel
	publisherChan chan *AmqpPublishMessage
}

func SetupAMQPEventPublisher(channel *amqp.Channel) *AMQPEventPublisher {
	publisherChan := make(chan *AmqpPublishMessage, 100)
	go func() {
		for {
			select {
			case amqpMessage := <-publisherChan:
				//TODO: When an error is obtained whiel publishing, retry/enque message
				amqpErr := channel.Publish(
					Exchange,
					amqpMessage.RoutingKey,
					amqpMessage.Mandatory,
					amqpMessage.Immediate,
					amqpMessage.Msg,
				)
				if amqpErr != nil {
					log.Errorf("error while publishing to AMQP queue: %s", amqpErr)
				}
			}
		}
	}()

	return &AMQPEventPublisher{
		channel:       channel,
		publisherChan: publisherChan,
	}
}

func (aPub AMQPEventPublisher) PublishCloudEvent(eventType string, eventSource string, payload interface{}) {
	event := buildCloudEvent(eventType, eventSource, payload)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		log.Errorf("error while serializing event: %s", marshalErr)
		return
	}

	log.Tracef("publishing event: Type=%s Source=%s \n%s", eventType, eventSource, string(eventBytes))

	aPub.publisherChan <- &AmqpPublishMessage{
		RoutingKey: event.Type(),
		Mandatory:  false,
		Immediate:  false,
		Msg: amqp.Publishing{
			ContentType: "text/json",
			Body:        []byte(eventBytes),
		},
	}

}

func buildCloudEvent(eventType string, eventSource string, payload interface{}) event.Event {
	event := cloudevents.NewEvent()
	event.SetSpecVersion("1.0")
	event.SetSource(eventSource)
	event.SetType(eventType)
	event.SetTime(time.Now())
	event.SetID(goid.NewV4UUID().String())
	event.SetData(cloudevents.ApplicationJSON, payload)
	return event
}

func SetupAMQPEventSubscriber(channel *amqp.Channel, serviceName string, routingKeys []string) (<-chan amqp.Delivery, error) {
	q, err := channel.QueueDeclare(
		serviceName, // name
		false,       // durable
		false,       // delete when unused
		true,        // exclusive
		false,       // no-wait
		nil,         // arguments
	)
	if err != nil {
		return nil, err
	}

	for _, rKey := range routingKeys {
		err = channel.QueueBind(
			q.Name,   // queue name
			rKey,     // routing key
			Exchange, // exchange
			false,
			nil,
		)
		if err != nil {
			return nil, err
		}
	}

	msgs, err := channel.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto ack
		false,  // exclusive
		false,  // no local
		false,  // no wait
		nil,    // args
	)
	if err != nil {
		return nil, err
	}

	return msgs, nil
}

func ParseCloudEvent(msg []byte) (*event.Event, error) {
	var event cloudevents.Event
	err := json.Unmarshal(msg, &event)
	if err != nil {
		return nil, err
	}

	return &event, nil
}
