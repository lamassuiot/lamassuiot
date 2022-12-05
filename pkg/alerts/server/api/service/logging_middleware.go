package service

import (
	"context"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
	log "github.com/sirupsen/logrus"
)

type Middleware func(Service) Service

func LoggingMiddleware() Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next: next,
		}
	}
}

type loggingMiddleware struct {
	next Service
}

func (mw loggingMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "Health"
		logMsg["took"] = time.Since(begin)

		log.WithFields(logMsg).Trace("")
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) HandleEvent(ctx context.Context, input *api.HandleEventInput) (output *api.HandleEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "HandleEvent"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %s", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.HandleEvent(ctx, input)
}

func (mw loggingMiddleware) SubscribedEvent(ctx context.Context, input *api.SubscribeEventInput) (output *api.SubscribeEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "SubscribedEvent"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.SubscribedEvent(ctx, input)
}

func (mw loggingMiddleware) UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (output *api.UnsubscribedEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UnsubscribedEvent"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UnsubscribedEvent(ctx, input)
}

func (mw loggingMiddleware) GetEventLogs(ctx context.Context, input *api.GetEventsInput) (output []cloudevents.Event, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetEventLogs"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %s", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetEventLogs(ctx, input)
}

func (mw loggingMiddleware) GetSubscriptions(ctx context.Context, input *api.GetSubscriptionsInput) (output *api.GetSubscriptionsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetSubscriptions"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetSubscriptions(ctx, input)
}
