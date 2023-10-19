package amqppub

import (
	"encoding/json"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	log "github.com/sirupsen/logrus"
	"github.com/streadway/amqp"
)

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
