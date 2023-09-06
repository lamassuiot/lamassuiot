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

type subscribesInfo struct {
	serviceName string
	routingKeys []string
}

type AMQPSetup struct {
	Channel        *amqp.Channel
	PublisherChan  chan *AmqpPublishMessage
	Msgs           <-chan amqp.Delivery
	subscribesInfo []subscribesInfo
}

func SetupAMQPConnection(logger *logrus.Entry, config config.AMQPConnection) (*AMQPSetup, error) {
	log = logger
	amqpCloseChan := make(chan *amqp.Error) //error channel

	var connection *amqp.Connection

	amqpEventPub := &AMQPSetup{}

	connection, err := amqpEventPub.buildAMQPConnection(config)
	if err != nil {
		return nil, err
	}

	connection.NotifyClose(amqpCloseChan)

	go func() {
		for {
			select { //check connection
			case err = <-amqpCloseChan:
				//work with error
				if err != nil {
					log.Errorf("disconnected from AMQP: %s", err)
					for {
						connection, err = amqpEventPub.buildAMQPConnection(config)

						if err != nil {
							log.Errorf("failed to reconnect. Sleeping for 5 seconds: %s", err)
							time.Sleep(5 * time.Second)
						} else {
							for _, subs := range amqpEventPub.subscribesInfo {
								amqpEventPub.SetupAMQPEventSubscriber(subs.serviceName, subs.routingKeys)
							}
							amqpCloseChan = make(chan *amqp.Error)
							connection.NotifyClose(amqpCloseChan)
							break
						}
					}
					log.Info("AMQP reconnection success")
				}
			}
		}
	}()

	return amqpEventPub, nil
}

func (aPub *AMQPSetup) buildAMQPConnection(cfg config.AMQPConnection) (*amqp.Connection, error) {
	userPassUrlPrefix := ""
	if cfg.BasicAuth.Enabled {
		log.Debugf("basic auth enabled")
		userPassUrlPrefix = fmt.Sprintf("%s:%s@", url.PathEscape(cfg.BasicAuth.Username), url.PathEscape(cfg.BasicAuth.Password))
	}

	amqpTlsConfig := tls.Config{}
	certPool := helpers.LoadSystemCACertPoolWithExtraCAsFromFiles([]string{cfg.CACertificateFile})
	amqpTlsConfig.RootCAs = certPool

	if cfg.InsecureSkipVerify {
		log.Debugf("tls InsecureSkipVerify set")
		amqpTlsConfig.InsecureSkipVerify = true
	}

	if cfg.ClientTLSAuth.Enabled {
		log.Debugf("tls loading mTLS client auth")
		clientTLSCerts, err := tls.LoadX509KeyPair(cfg.ClientTLSAuth.CertFile, cfg.ClientTLSAuth.KeyFile)
		if err != nil {
			log.Errorf("could not load AMQP client TLS certificate or key: %s", err)
			return nil, err
		}

		amqpTlsConfig.Certificates = append(amqpTlsConfig.Certificates, clientTLSCerts)
	}

	amqpURL := fmt.Sprintf("%s://%s%s:%d", cfg.Protocol, userPassUrlPrefix, cfg.Hostname, cfg.Port)
	log.Debugf("AMQP Broker URL: %s", amqpURL)
	amqpConn, err := amqp.DialTLS(amqpURL, &amqpTlsConfig)
	if err != nil {
		log.Errorf("failed to connect to AMQP broker: %s", err)
		return nil, err
	}

	amqpChannel, err := amqpConn.Channel()
	if err != nil {
		log.Errorf("could not create AMQP channel: %s", err)
		return nil, err
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
		return nil, err
	}
	aPub.Channel = amqpChannel
	aPub.setupAMQPEventPublisher()
	log.Debugf("exchange created")
	return amqpConn, nil

}

func (aPub *AMQPSetup) setupAMQPEventPublisher() {
	publisherChan := make(chan *AmqpPublishMessage, 100)
	go func() {
		for {
			select {
			case amqpMessage := <-publisherChan:
				//TODO: When an error is obtained whiel publishing, retry/enque message
				amqpErr := aPub.Channel.Publish(
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
	aPub.PublisherChan = publisherChan
}

func (aPub *AMQPSetup) PublishCloudEvent(eventType string, eventSource string, payload interface{}) {
	event := buildCloudEvent(eventType, eventSource, payload)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		log.Errorf("error while serializing event: %s", marshalErr)
		return
	}

	log.Tracef("publishing event: Type=%s Source=%s \n%s", eventType, eventSource, string(eventBytes))

	aPub.PublisherChan <- &AmqpPublishMessage{
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

func (aPub *AMQPSetup) SetupAMQPEventSubscriber(serviceName string, routingKeys []string) error {
	if !serviceNameExist(aPub.subscribesInfo, serviceName) {
		aPub.subscribesInfo = append(aPub.subscribesInfo, subscribesInfo{serviceName: serviceName, routingKeys: routingKeys})
	}
	q, err := aPub.Channel.QueueDeclare(
		serviceName, // name
		false,       // durable
		false,       // delete when unused
		false,       // exclusive
		false,       // no-wait
		nil,         // arguments
	)
	if err != nil {
		return err
	}

	for _, rKey := range routingKeys {
		err = aPub.Channel.QueueBind(
			q.Name,   // queue name
			rKey,     // routing key
			Exchange, // exchange
			false,
			nil,
		)
		if err != nil {
			return err
		}
	}

	msgs, err := aPub.Channel.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto ack
		false,  // exclusive
		false,  // no local
		false,  // no wait
		nil,    // args
	)
	if err != nil {
		return err
	}
	aPub.Msgs = msgs
	return nil
}

func ParseCloudEvent(msg []byte) (*event.Event, error) {
	var event cloudevents.Event
	err := json.Unmarshal(msg, &event)
	if err != nil {
		return nil, err
	}

	return &event, nil
}

func serviceNameExist(subscribeInfo []subscribesInfo, serviceName string) bool {
	for _, info := range subscribeInfo {
		if info.serviceName == serviceName {
			return true
		}
	}
	return false
}
