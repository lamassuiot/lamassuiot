package transport

import (
	"context"
	"encoding/base64"
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	amqptransport "github.com/go-kit/kit/transport/amqp"
	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	"github.com/streadway/amqp"
)

func MakeAmqpHandler(s service.Service, logger log.Logger) *amqptransport.Subscriber {
	endpoints := endpoint.MakeServerEndpoints(s)
	options := []amqptransport.SubscriberOption{}

	// AMQP Subscribers
	lamassuEventsSubscriber := amqptransport.NewSubscriber(
		endpoints.EventHandlerEndpoint,
		decodeCloudEventAMQPRequest,
		amqptransport.EncodeJSONResponse,
		append(
			options,
		)...,
	)

	return lamassuEventsSubscriber
}

func DecodeB64(message string) (string, error) {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	_, err := base64.StdEncoding.Decode(base64Text, []byte(message))
	return string(base64Text), err
}

func decodeCloudEventAMQPRequest(ctx context.Context, delivery *amqp.Delivery) (interface{}, error) {
	var event cloudevents.Event
	err := json.Unmarshal(delivery.Body, &event)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	return event, nil
}
