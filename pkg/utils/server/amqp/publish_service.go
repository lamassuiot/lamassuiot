package amqp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	log "github.com/sirupsen/logrus"

	"github.com/streadway/amqp"
)

type PublishService struct {
	source      string
	eventPrefix string
	publisher   chan server.AmqpPublishMessage
}

func NewPublishService(source string, eventPrefix string, amqpPublisher chan server.AmqpPublishMessage) PublishService {
	return PublishService{
		source:      source,
		eventPrefix: eventPrefix,
		publisher:   amqpPublisher,
	}
}

func (amqpSvc *PublishService) createEvent(ctx context.Context, version string, eventType string, data interface{}) event.Event {
	event := cloudevents.NewEvent()
	event.SetSpecVersion(version)
	event.SetSource(amqpSvc.source)
	event.SetType(fmt.Sprintf("%s.%s", amqpSvc.eventPrefix, eventType))
	event.SetTime(time.Now())
	event.SetData(cloudevents.ApplicationJSON, data)
	return event
}

func (amqpSvc *PublishService) SendAMQPMessage(ctx context.Context, eventType string, output interface{}) {
	event := amqpSvc.createEvent(ctx, "1.0", eventType, output)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		log.Error("Error while serializing event: ", marshalErr)
	}

	msg := server.AmqpPublishMessage{
		Exchange:  "lamassu",
		Key:       eventType,
		Mandatory: false,
		Immediate: false,
		Msg: amqp.Publishing{
			ContentType: "text/json",
			Body:        []byte(eventBytes),
			Headers: amqp.Table{
				"traceparent": event.ID(),
			},
		},
	}

	amqpSvc.publisher <- msg
}
