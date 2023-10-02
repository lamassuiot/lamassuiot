package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	log "github.com/sirupsen/logrus"

	"github.com/streadway/amqp"
)

const Source = "lamassuiot/dms-manager"
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
	amqpPublisher chan server.AmqpPublishMessage
	next          Service
}

func NewAMQPMiddleware(amqpPublisher chan server.AmqpPublishMessage) Middleware {
	return func(next Service) Service {
		return &amqpMiddleware{
			amqpPublisher: amqpPublisher,
			next:          next,
		}
	}
}

func (mw *amqpMiddleware) sendAMQPMessage(eventType string, output interface{}) {
	event := CreateEvent(context.Background(), "1.0", Source, eventType, output)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		log.Error("Error while serializing event: ", marshalErr)
	}

	msg := server.AmqpPublishMessage{
		Exchange:  "lamassu",
		Key:       eventType,
		Mandatory: false,
		Immediate: false,
		Msg: amqp.Publishing{
			ContentType: "text/json",
			Body:        []byte(eventBytes),
		},
	}

	mw.amqpPublisher <- msg

}
func (mw *amqpMiddleware) UpdateDevManagerAddr(devManagerAddr string) {
}

func (mw *amqpMiddleware) Health(ctx context.Context) bool {
	return mw.next.Health(ctx)
}

func (mw *amqpMiddleware) CreateDMS(ctx context.Context, input *api.CreateDMSInput) (output *api.CreateDMSOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.dms.create", EventPrefix), output.Serialize())
		}
	}()
	return mw.next.CreateDMS(ctx, input)
}

func (mw *amqpMiddleware) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (output *api.UpdateDMSStatusOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.dms.update-status", EventPrefix), output.Serialize())
		}
	}()
	return mw.next.UpdateDMSStatus(ctx, input)
}

func (mw *amqpMiddleware) UpdateDMS(ctx context.Context, input *api.UpdateDMSInput) (output *api.UpdateDMSOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.dms.update", EventPrefix), output.Serialize())
		}
	}()
	return mw.next.UpdateDMS(ctx, input)
}

func (mw *amqpMiddleware) UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (output *api.UpdateDMSAuthorizedCAsOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.dms.update-authorizedcas", EventPrefix), output.Serialize())
		}
	}()
	return mw.next.UpdateDMSAuthorizedCAs(ctx, input)
}

func (mw *amqpMiddleware) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error) {
	return mw.next.GetDMSs(ctx, input)
}

func (mw *amqpMiddleware) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error) {
	return mw.next.GetDMSByName(ctx, input)
}

func (mw *amqpMiddleware) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return mw.next.CACerts(ctx, aps)
}

func (mw *amqpMiddleware) Enroll(ctx context.Context, csr *x509.CertificateRequest, certChain []*x509.Certificate, aps string) (output *x509.Certificate, err error) {
	return mw.next.Enroll(ctx, csr, certChain, aps)
}

func (mw *amqpMiddleware) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (output *x509.Certificate, err error) {

	return mw.next.Reenroll(ctx, csr, cert, aps)
}

func (mw *amqpMiddleware) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return mw.next.ServerKeyGen(ctx, csr, cert, aps)
}
