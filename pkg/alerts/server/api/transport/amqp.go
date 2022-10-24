package transport

import (
	"context"
	"encoding/json"
	"fmt"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	amqptransport "github.com/go-kit/kit/transport/amqp"
	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	serverUtils "github.com/lamassuiot/lamassuiot/pkg/utils/server"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/streadway/amqp"
	"go.opentelemetry.io/otel/trace"
)

func EndTracingFromContext() amqptransport.SubscriberResponseFunc {
	return func(ctx context.Context, del *amqp.Delivery, ch amqptransport.Channel, pub *amqp.Publishing) context.Context {
		span := trace.SpanFromContext(ctx)
		fmt.Println("end ", span.SpanContext().SpanID().String())
		span.End()
		return ctx
	}
}

func MakeAmqpHandler(s service.Service, logger log.Logger, otTracer stdopentracing.Tracer) *amqptransport.Subscriber {
	endpoints := endpoint.MakeServerEndpoints(s, otTracer)
	options := []amqptransport.SubscriberOption{
		amqptransport.SubscriberBefore(serverUtils.InjectTracingToContextFromAMQP()),
	}

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
