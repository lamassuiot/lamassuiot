package amqppub

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
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	log "github.com/sirupsen/logrus"
	"github.com/streadway/amqp"
)

type AmqpPublishMessage struct {
	Exchange  string
	Key       string
	Mandatory bool
	Immediate bool
	Msg       amqp.Publishing
}

type amqpHandler struct {
	AmqpConnection      *amqp.Connection
	PublisherChan       chan *AmqpPublishMessage
	amqpChannel         *amqp.Channel
	amqpChanNotifyClose chan *amqp.Error
	amqpConfig          config.AMQPConnection
}

func SetupAMQPConnection(config config.AMQPConnection) (*amqpHandler, error) {
	handler := &amqpHandler{
		amqpConfig: config,
	}
	err := handler.buildAMQPConnection(config)
	if err != nil {
		return nil, err
	}

	// amqpCloseChan := amqpConnection.NotifyClose(make(chan *amqp.Error)) //error channel
	// publisherChan := make(chan *AmqpPublishMessage, 100)

	go func() {
		for {
			select { //check connection
			case err = <-handler.amqpChanNotifyClose:
				//work with error
				log.Errorf("disconnected from AMQP: %s", err)
				for {
					err = handler.buildAMQPConnection(config)
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

	return handler, nil
}

func (h *amqpHandler) buildAMQPConnection(cfg config.AMQPConnection) error {
	userPassUrlPrefix := ""
	if cfg.BasicAuth.Enabled {
		userPassUrlPrefix = fmt.Sprintf("%s:%s@", url.PathEscape(cfg.BasicAuth.Username), url.PathEscape(string(cfg.BasicAuth.Password)))
	}

	amqpTlsConfig := tls.Config{}
	certPool := helpers.LoadSystemCACertPoolWithExtraCAsFromFiles([]string{cfg.CACertificateFile})
	amqpTlsConfig.RootCAs = certPool

	if cfg.InsecureSkipVerify {
		amqpTlsConfig.InsecureSkipVerify = true
	}

	if cfg.ClientTLSAuth.Enabled {
		clientTLSCerts, err := tls.LoadX509KeyPair(cfg.ClientTLSAuth.CertFile, cfg.ClientTLSAuth.KeyFile)
		if err != nil {
			log.Error("could not load AMQP client TLS certificate or key: ", err)
			return err
		}

		amqpTlsConfig.Certificates = append(amqpTlsConfig.Certificates, clientTLSCerts)
	}

	amqpURL := fmt.Sprintf("%s://%s%s:%d", cfg.Protocol, userPassUrlPrefix, cfg.Hostname, cfg.Port)
	amqpConn, err := amqp.DialTLS(amqpURL, &amqpTlsConfig)
	if err != nil {
		log.Error("failed to connect to AMQP broker: ", err)
		return err
	}
	publisherChan := make(chan *AmqpPublishMessage, 100)

	amqpChannel, err := amqpConn.Channel()
	if err != nil {
		return err
	}

	err = amqpChannel.ExchangeDeclare(
		"lamassu", // name
		"topic",   // type
		true,      // durable
		false,     // auto-deleted
		false,     // internal
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case amqpMessage := <-publisherChan:
				//TODO: When an error is obtained whiel publishing, retry/enque message
				amqpErr := amqpChannel.Publish(amqpMessage.Exchange, amqpMessage.Key, amqpMessage.Mandatory, amqpMessage.Immediate, amqpMessage.Msg)
				if amqpErr != nil {
					log.Errorf("error while publishing to AMQP queue: %s", amqpErr)
				}
			}
		}
	}()

	h.AmqpConnection = amqpConn
	h.PublisherChan = publisherChan
	h.amqpChanNotifyClose = amqpConn.NotifyClose(make(chan *amqp.Error))
	h.amqpChannel = amqpChannel

	return nil
}

func (mw amqpEventPublisher) publishEvent(eventType string, eventSource string, payload interface{}) {
	event := buildCloudEvent(eventType, eventSource, payload)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		log.Errorf("error while serializing event: %s", marshalErr)
		return
	}

	mw.eventPublisher.PublisherChan <- &messaging.AmqpPublishMessage{
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
