package service

import (
	"context"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
)

type Middleware func(Service) Service

func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMiddleware struct {
	next   Service
	logger log.Logger
}

func (mw loggingMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) HandleEvent(ctx context.Context, input *api.HandleEventInput) (output *api.HandleEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "HandleEvent")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.HandleEvent(ctx, input)
}

func (mw loggingMiddleware) SubscribedEvent(ctx context.Context, input *api.SubscribeEventInput) (output *api.SubscribeEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "SubscribedEvent")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output.ToSerializedLog())
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.SubscribedEvent(ctx, input)
}

func (mw loggingMiddleware) UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (output *api.UnsubscribedEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UnsubscribedEvent")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output.ToSerializedLog())
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.UnsubscribedEvent(ctx, input)
}

func (mw loggingMiddleware) GetEventLogs(ctx context.Context, input *api.GetEventsInput) (output []cloudevents.Event, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetEventLogs")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output)
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.GetEventLogs(ctx, input)
}

func (mw loggingMiddleware) GetSubscriptions(ctx context.Context, input *api.GetSubscriptionsInput) (output *api.GetSubscriptionsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetSubscriptions")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output.ToSerializedLog())
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.GetSubscriptions(ctx, input)
}
