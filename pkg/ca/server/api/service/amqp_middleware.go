package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"

	"github.com/streadway/amqp"
)

const Source = "lamassuiot/ca"
const EventPrefix = "io.lamassuiot"

func CreateEvent(ctx context.Context, version string, source string, eventType string, data interface{}) event.Event {
	// trace_id := opentracing.SpanFromContext(ctx)
	trace_id := goid.NewV4UUID().String()
	event := cloudevents.NewEvent()
	event.SetSpecVersion(version)
	event.SetSource(source)
	event.SetType(eventType)
	event.SetTime(time.Now())
	event.SetID(trace_id)
	event.SetData(cloudevents.ApplicationJSON, data)
	return event
}

type amqpMiddleware struct {
	amqpChannel *amqp.Channel
	logger      log.Logger
	next        Service
}

func NewAMQPMiddleware(channel *amqp.Channel, logger log.Logger) Middleware {
	return func(next Service) Service {
		return &amqpMiddleware{
			amqpChannel: channel,
			logger:      logger,
			next:        next,
		}
	}
}

func (mw *amqpMiddleware) sendAMQPMessage(eventType string, output interface{}) {
	event := CreateEvent(context.Background(), "1.0", Source, eventType, output)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		level.Error(mw.logger).Log("msg", "Error while serializing event", "err", marshalErr)
	}

	amqpErr := mw.amqpChannel.Publish("", "lamassu_events", false, false, amqp.Publishing{
		ContentType: "text/json",
		Body:        []byte(eventBytes),
	})
	if amqpErr != nil {
		level.Error(mw.logger).Log("msg", "Error while publishing to AMQP queue", "err", amqpErr)
	}
}

func (mw *amqpMiddleware) Health() (healthy bool) {
	return mw.next.Health()
}

func (mw *amqpMiddleware) GetEngineProviderInfo() (output api.EngineProviderInfo) {
	return mw.next.GetEngineProviderInfo()
}

func (mw *amqpMiddleware) Stats(ctx context.Context, input *api.GetStatsInput) (output *api.GetStatsOutput, err error) {
	return mw.next.Stats(ctx, input)
}

func (mw *amqpMiddleware) CreateCA(ctx context.Context, input *api.CreateCAInput) (output *api.CreateCAOutput, err error) {
	mw.sendAMQPMessage(fmt.Sprintf("%s.ca.create", EventPrefix), output.Serialize())
	return mw.next.CreateCA(ctx, input)
}

func (mw *amqpMiddleware) GetCAs(ctx context.Context, input *api.GetCAsInput) (output *api.GetCAsOutput, err error) {
	return mw.next.GetCAs(ctx, input)
}

func (mw *amqpMiddleware) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (output *api.GetCAByNameOutput, err error) {
	return mw.next.GetCAByName(ctx, input)
}

func (mw *amqpMiddleware) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (output *api.UpdateCAStatusOutput, err error) {
	mw.sendAMQPMessage(fmt.Sprintf("%s.ca.update", EventPrefix), output.Serialize())
	return mw.next.UpdateCAStatus(ctx, input)
}

func (mw *amqpMiddleware) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (output *api.RevokeCAOutput, err error) {
	mw.sendAMQPMessage(fmt.Sprintf("%s.ca.revoke", EventPrefix), output.Serialize())
	return mw.next.RevokeCA(ctx, input)
}

func (mw *amqpMiddleware) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (output *api.IterateCAsWithPredicateOutput, err error) {
	return mw.next.IterateCAsWithPredicate(ctx, input)
}

func (mw *amqpMiddleware) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (output *api.SignCertificateRequestOutput, err error) {
	mw.sendAMQPMessage(fmt.Sprintf("%s.certificate.sign", EventPrefix), output.Serialize())
	return mw.next.SignCertificateRequest(ctx, input)
}

func (mw *amqpMiddleware) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (output *api.RevokeCertificateOutput, err error) {
	mw.sendAMQPMessage(fmt.Sprintf("%s.certificate.revoke", EventPrefix), output.Serialize())
	return mw.next.RevokeCertificate(ctx, input)
}

func (mw *amqpMiddleware) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (output *api.GetCertificateBySerialNumberOutput, err error) {
	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw *amqpMiddleware) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (output *api.GetCertificatesOutput, err error) {
	mw.sendAMQPMessage(fmt.Sprintf("%s.certificate.sign", EventPrefix), output.Serialize())
	return mw.next.GetCertificates(ctx, input)
}

func (mw *amqpMiddleware) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (output *api.UpdateCertificateStatusOutput, err error) {
	mw.sendAMQPMessage(fmt.Sprintf("%s.certificate.update", EventPrefix), output.Serialize())
	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw *amqpMiddleware) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (output *api.IterateCertificatesWithPredicateOutput, err error) {
	return mw.next.IterateCertificatesWithPredicate(ctx, input)
}
