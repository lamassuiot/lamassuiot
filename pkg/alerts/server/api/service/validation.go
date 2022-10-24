package service

import (
	"context"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/errors"
)

type validationMiddleware struct {
	next Service
}

func NewInputValudationMiddleware() Middleware {
	return func(next Service) Service {
		return &validationMiddleware{
			next: next,
		}
	}
}

func (mw *validationMiddleware) Health(ctx context.Context) (healthy bool) {
	return mw.next.Health(ctx)
}

func (mw *validationMiddleware) HandleEvent(ctx context.Context, input *api.HandleEventInput) (output *api.HandleEventOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.HandleEvent(ctx, input)
}

func (mw *validationMiddleware) SubscribedEvent(ctx context.Context, input *api.SubscribeEventInput) (output *api.SubscribeEventOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.SubscribedEvent(ctx, input)
}

func (mw *validationMiddleware) UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (output *api.UnsubscribedEventOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UnsubscribedEvent(ctx, input)
}

func (mw *validationMiddleware) GetEventLogs(ctx context.Context, input *api.GetEventsInput) (output []cloudevents.Event, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetEventLogs(ctx, input)
}

func (mw *validationMiddleware) GetSubscriptions(ctx context.Context, input *api.GetSubscriptionsInput) (output *api.GetSubscriptionsOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetSubscriptions(ctx, input)
}
