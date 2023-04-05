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
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
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

func SetupAMQPConnection(config config.AMQPConnection) (*amqp.Channel, chan *AmqpPublishMessage, error) {
	amqpConnection, err := buildAMQPConnection(config)
	if err != nil {
		return nil, nil, err
	}

	amqpCloseChan := amqpConnection.NotifyClose(make(chan *amqp.Error)) //error channel
	go func() {
		for {
			select { //check connection
			case err = <-amqpCloseChan:
				//work with error
				log.Errorf("disconnected from AMQP: %s", err)
				for {
					amqpConnection, err = buildAMQPConnection(config)
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

	amqpChannel, err := amqpConnection.Channel()
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}

	publisherChan := make(chan *AmqpPublishMessage, 100)

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

	return amqpChannel, publisherChan, nil
}

func buildAMQPConnection(cfg config.AMQPConnection) (*amqp.Connection, error) {
	userPassUrlPrefix := ""
	if cfg.BasicAuth.Enabled {
		userPassUrlPrefix = fmt.Sprintf("%s:%s@", url.PathEscape(cfg.BasicAuth.Username), url.PathEscape(cfg.BasicAuth.Password))
	}

	amqpTlsConfig := tls.Config{}
	certPool := helppers.LoadSytemCACertPoolWithExtraCAsFromFiles([]string{cfg.CACertificateFile})
	amqpTlsConfig.RootCAs = certPool

	if cfg.InsecureSkipVerify {
		amqpTlsConfig.InsecureSkipVerify = true
	}

	if cfg.ClientTLSAuth.Enabled {
		clientTLSCerts, err := tls.LoadX509KeyPair(cfg.ClientTLSAuth.CertFile, cfg.ClientTLSAuth.KeyFile)
		if err != nil {
			log.Error("could not load AMQP client TLS certificate or key: ", err)
			return nil, err
		}

		amqpTlsConfig.Certificates = append(amqpTlsConfig.Certificates, clientTLSCerts)
	}

	amqpURL := fmt.Sprintf("%s://%s%s:%d", cfg.Protocol, userPassUrlPrefix, cfg.Hostname, cfg.Port)
	amqpConn, err := amqp.DialTLS(amqpURL, &amqpTlsConfig)
	if err != nil {
		log.Error("failed to connect to AMQP broker: ", err)
		return nil, err
	}

	return amqpConn, nil
}

func (mw amqpEventPublisher) publishEvent(eventType string, eventSource string, payload interface{}) {
	event := buildCloudEvent(eventType, eventSource, payload)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		log.Errorf("error while serializing event: %s", marshalErr)
		return
	}

	mw.amqpPublisher <- &AmqpPublishMessage{
		Exchange:  "lamassu",
		Key:       event.Type(),
		Mandatory: false,
		Immediate: false,
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
