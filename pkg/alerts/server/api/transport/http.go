package transport

import (
	"context"
	"encoding/json"
	"net/http"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"
	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/endpoint"
	lamassuErrors "github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
	}

	r.Methods("GET").Path("/health").Handler(
		otelhttp.NewHandler(
			httptransport.NewServer(
				e.HealthEndpoint,
				decodeHealthRequest,
				encodeResponse,
				append(
					options,
				)...,
			),
			"Health",
		),
	)

	r.Methods("POST").Path("/subscribe").Handler(
		otelhttp.NewHandler(
			httptransport.NewServer(
				e.SubscribedEventEndpoint,
				decodeSubscribedEventRequest,
				encodeSubscribedEventResponse,
				append(
					options,
				)...,
			),
			"SubscribedEvent",
		),
	)

	r.Methods("POST").Path("/unsubscribe").Handler(
		otelhttp.NewHandler(
			httptransport.NewServer(
				e.UnsubscribedEventEndpoint,
				decodeUnsubscribedEventRequest,
				encodeUnsubscribedEventResponse,
				append(
					options,
				)...,
			),
			"UnsubscribedEvent",
		),
	)

	r.Methods("GET").Path("/lastevents").Handler(
		otelhttp.NewHandler(
			httptransport.NewServer(
				e.GetEventsEndpoint,
				decodeGetEventsRequest,
				encodeGetEventsResponse,
				append(
					options,
				)...,
			),
			"GetEvents",
		),
	)

	r.Methods("GET").Path("/subscriptions/{userID}").Handler(
		otelhttp.NewHandler(
			httptransport.NewServer(
				e.GetSubscriptionsEndpoint,
				decodeGetSubscriptionRequest,
				encodeGetSubscriptionsResponse,
				append(
					options,
				)...,
			),
			"GetSubscriptions",
		),
	)

	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.HealthRequest
	return req, nil
}

func decodeGetSubscriptionRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var input api.GetSubscriptionsInput

	vars := mux.Vars(r)
	input.UserID = vars["userID"]

	return input, nil
}

func decodeSubscribedEventRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var input api.SubscribeEventInput
	var body api.SubscribedEventPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	input = api.SubscribeEventInput{
		EventType:  body.EventType,
		Conditions: body.Conditions,
		UserID:     body.UserID,
		Channel: api.ChannelCreation{
			Type:   body.Channel.Type,
			Name:   body.Channel.Name,
			Config: body.Channel.Config,
		},
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
	if body.UserID == "" {
		return nil, ErrMissingUserID()
	}
	if body.SubscriptionID == "" {
		return nil, ErrMissingConnectorID()
	}

	input = api.UnsubscribedEventInput{
		UserID:         body.UserID,
		SubscriptionID: body.SubscriptionID,
	}

	return input, nil
}

func decodeGetEventsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	return api.GetEventsInput{}, nil
}

// func encodeGetSynchronizedCAsByConnectorRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
// 	encodeResponse()
// }

func encodeGetSubscriptionsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	castedResponse := response.(*api.GetSubscriptionsOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeGetEventsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	castedResponse := response.([]cloudevents.Event)
	serializedResponse := castedResponse

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
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
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeSubscribedEventResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	castedResponse := response.(*api.SubscribeEventOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(serializedResponse)
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
