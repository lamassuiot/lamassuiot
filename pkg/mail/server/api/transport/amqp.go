package transport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	amqptransport "github.com/go-kit/kit/transport/amqp"
	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/streadway/amqp"
)

func AddLoggerToContext(logger log.Logger, otTracer stdopentracing.Tracer) amqptransport.RequestFunc {
	return func(ctx context.Context, pub *amqp.Publishing, del *amqp.Delivery) context.Context {
		span, ctx := stdopentracing.StartSpanFromContextWithTracer(ctx, otTracer, "event-handler")
		logger = log.With(logger, "span_id", span)
		//return context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)
		return ctx
	}
}

func MakeAmqpHandler(s service.Service, logger log.Logger, otTracer stdopentracing.Tracer) *amqptransport.Subscriber {
	endpoints := endpoint.MakeServerEndpoints(s, otTracer)
	options := []amqptransport.SubscriberOption{
		amqptransport.SubscriberBefore(AddLoggerToContext(logger, otTracer)),
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

func DecodeB64(message string) (string, error) {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	_, err := base64.StdEncoding.Decode(base64Text, []byte(message))
	return string(base64Text), err
}

func decodeCloudEventAMQPRequest(ctx context.Context, delivery *amqp.Delivery) (interface{}, error) {
	/*logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	level.Debug(logger).Log("msg", "Event request received")*/
	fmt.Println(string(delivery.Body))

	var event cloudevents.Event
	err := json.Unmarshal(delivery.Body, &event)
	if err != nil {
		//level.Debug(logger).Log("msg", "decoded event error", "err", err)
		return nil, err
	}
	//level.Debug(logger).Log("msg", "decoded event", "event", event)

	if err != nil {
		return nil, err
	}

	return event, nil
}
