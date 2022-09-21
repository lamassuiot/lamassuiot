package endpoint

import (
	"context"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
	"go.opentelemetry.io/contrib/instrumentation/github.com/go-kit/kit/otelkit"
)

type Endpoints struct {
	HealthEndpoint                 endpoint.Endpoint
	EventHandlerEndpoint           endpoint.Endpoint
	SubscribedEventEndpoint        endpoint.Endpoint
	UnsubscribedEventEndpoint      endpoint.Endpoint
	GetEventsEndpoint              endpoint.Endpoint
	CheckMailConfigirationEndpoint endpoint.Endpoint
	GetSubscriptionsEndpoint       endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = otelkit.EndpointMiddleware(otelkit.WithOperation("Health"))(healthEndpoint)
	}

	var eventHandlerEndpoint endpoint.Endpoint
	{
		eventHandlerEndpoint = MakeEventHandlerEndpoint(s)
		eventHandlerEndpoint = otelkit.EndpointMiddleware(otelkit.WithOperation("EventHandlerEndpoint"))(eventHandlerEndpoint)
	}

	var subscribedEventEndpoint endpoint.Endpoint
	{
		subscribedEventEndpoint = MakeSubscribedEventEndpoint(s)
		subscribedEventEndpoint = opentracing.TraceServer(otTracer, "SubscribedEventEndpoint")(subscribedEventEndpoint)
	}

	var unsubscribedEventEndpoint endpoint.Endpoint
	{
		unsubscribedEventEndpoint = MakeUnsubscribedEventEndpoint(s)
		unsubscribedEventEndpoint = opentracing.TraceServer(otTracer, "UnsubscribedEventEndpoint")(unsubscribedEventEndpoint)
	}
	var getEventsEndpoint endpoint.Endpoint
	{
		getEventsEndpoint = MakeGetEventsEndpoint(s)
		getEventsEndpoint = opentracing.TraceServer(otTracer, "GetLastEventEndpoint")(getEventsEndpoint)
	}

	var getSubscriptionsEndpoint endpoint.Endpoint
	{
		getSubscriptionsEndpoint = MakeGetSubscriptionsEndpoint(s)
		getSubscriptionsEndpoint = opentracing.TraceServer(otTracer, "GetSubscriptionsEndpoint")(getSubscriptionsEndpoint)
	}

	return Endpoints{
		HealthEndpoint:            healthEndpoint,
		EventHandlerEndpoint:      eventHandlerEndpoint,
		SubscribedEventEndpoint:   subscribedEventEndpoint,
		UnsubscribedEventEndpoint: unsubscribedEventEndpoint,
		GetEventsEndpoint:         getEventsEndpoint,
		GetSubscriptionsEndpoint:  getSubscriptionsEndpoint,
	}
}
func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}
func ValidateEventHandlerRequest(request cloudevents.Event) error {
	GetHandleEventRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.HandleEventInput)

	}
	validate := validator.New()
	validate.RegisterStructValidation(GetHandleEventRequestStructLevelValidation, api.HandleEventInput{})
	return validate.Struct(request)
}

func MakeEventHandlerEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		event := request.(cloudevents.Event)
		err := ValidateEventHandlerRequest(event)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		output, err := s.HandleEvent(ctx, &api.HandleEventInput{
			Event: event,
		})
		return output, err
	}
}

func ValidateSubscribedEventRequest(request api.SubscribeEventInput) error {
	SubscribedEventRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.SubscribeEventInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(SubscribedEventRequestStructLevelValidation, api.SubscribeEventInput{})
	return validate.Struct(request)
}

func MakeSubscribedEventEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		input := request.(api.SubscribeEventInput)

		err := ValidateSubscribedEventRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.SubscribedEvent(ctx, &input)
		return output, err
	}
}

func ValidateUnsubscribedEventRequest(request api.UnsubscribedEventInput) error {
	SubscribedEventRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.UnsubscribedEventInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(SubscribedEventRequestStructLevelValidation, api.UnsubscribedEventInput{})
	return validate.Struct(request)
}

func MakeUnsubscribedEventEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		input := request.(api.UnsubscribedEventInput)

		err := ValidateUnsubscribedEventRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.UnsubscribedEvent(ctx, &input)
		return output, err
	}
}

func ValidateGetEventsRequest(request api.GetEventsInput) error {
	GetEventsRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetEventsInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetEventsRequestStructLevelValidation, api.GetEventsInput{})
	return validate.Struct(request)
}

func MakeGetEventsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		input := request.(api.GetEventsInput)

		err := ValidateGetEventsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetEventLogs(ctx, &input)
		return output, err
	}
}

func ValidateGetSubscriptionsRequest(request api.GetSubscriptionsInput) error {
	GetSubscriptionsRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetSubscriptionsInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetSubscriptionsRequestStructLevelValidation, api.GetSubscriptionsInput{})
	return validate.Struct(request)
}

func MakeGetSubscriptionsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		input := request.(api.GetSubscriptionsInput)

		err := ValidateGetSubscriptionsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetSubscriptions(ctx, &input)
		return output, err
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type EmptyRequest struct{}
