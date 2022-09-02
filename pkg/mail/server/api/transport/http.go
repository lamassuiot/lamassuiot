package transport

import (
	"context"
	"encoding/json"
	"net/http"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"

	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/mail/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/endpoint"
	lamassuErrors "github.com/lamassuiot/lamassuiot/pkg/mail/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/service"
	utilstransport "github.com/lamassuiot/lamassuiot/pkg/utils/server/transport"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type errorer interface {
	error() error
}

func InvalidJsonFormat() error {
	return &lamassuErrors.GenericError{
		Message:    "Invalid JSON format",
		StatusCode: 400,
	}
}

func ErrMissingConnectorID() error {
	return &lamassuErrors.GenericError{
		Message:    "connectorID not specified",
		StatusCode: 400,
	}
}
func ErrMissingUserID() error {
	return &lamassuErrors.GenericError{
		Message:    "userId not specified",
		StatusCode: 400,
	}
}

func MakeHTTPHandler(s service.Service, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	r := mux.NewRouter()
	e := endpoint.MakeServerEndpoints(s, otTracer)
	options := []httptransport.ServerOption{
		httptransport.ServerBefore(utilstransport.HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
	}

	r.Methods("GET").Path("/health").Handler(httptransport.NewServer(
		e.HealthEndpoint,
		decodeHealthRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Health", logger)),
		)...,
	))

	r.Methods("POST").Path("/subscribe").Handler(httptransport.NewServer(
		e.SubscribedEventEndpoint,
		decodeSubscribedEventRequest,
		encodeSubscribedEventResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "SubscribedEventEndpoint", logger)),
		)...,
	))

	r.Methods("POST").Path("/unsubscribe").Handler(httptransport.NewServer(
		e.UnsubscribedEventEndpoint,
		decodeUnsubscribedEventRequest,
		encodeUnsubscribedEventResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "UnsubscribedEventEndpoint", logger)),
		)...,
	))
	r.Methods("GET").Path("/lastevents").Handler(httptransport.NewServer(
		e.GetEventsEndpoint,
		decodeGetEventsRequest,
		encodeGetEventsResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetEventsEndpoint", logger)),
		)...,
	))

	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.HealthRequest
	return req, nil
}

func decodeEmptyRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.EmptyRequest
	return req, nil
}

func decodeEventHandlerRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var event cloudevents.Event
	json.NewDecoder(r.Body).Decode((&event))
	return event, nil
}

func decodeSubscribedEventRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var input api.SubscribedEventInput
	var body api.SubscribedEventPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	input = api.SubscribedEventInput{
		Email:     body.Email,
		EventType: body.EventType,
	}

	return input, nil
}

func decodeUnsubscribedEventRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var input api.UnsubscribedEventInput
	var body api.UnsubscribedEventPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	input = api.UnsubscribedEventInput{
		Email:     body.Email,
		EventType: body.EventType,
	}

	return input, nil
}

func decodeGetEventsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	return api.GetEventsInput{}, nil
}

// func encodeGetSynchronizedCAsByConnectorRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
// 	encodeResponse()
// }

func encodeGetEventsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	castedResponse := response.(*api.GetEventsOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeUnsubscribedEventResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	castedResponse := response.(*api.UnsubscribedEventOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeSubscribedEventResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	castedResponse := response.(*api.SubscribedEventOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeEventHandlerResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}

	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(response)
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.

		// https://medium.com/@ozdemir.zynl/rest-api-error-handling-in-go-behavioral-type-assertion-509d93636afd
		//
		encodeError(ctx, e.error(), w)

		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeError(ctx context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	w.WriteHeader(codeFrom(err))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()})

}

type errorWrapper struct {
	Error string `json:"error"`
}

func codeFrom(err error) int {
	switch e := err.(type) {
	case *lamassuErrors.ValidationError:
		return http.StatusBadRequest
	case *lamassuErrors.DuplicateResourceError:
		return http.StatusConflict
	case *lamassuErrors.ResourceNotFoundError:
		return http.StatusNotFound
	case *lamassuErrors.GenericError:
		return e.StatusCode
	default:
		return http.StatusInternalServerError
	}
}
