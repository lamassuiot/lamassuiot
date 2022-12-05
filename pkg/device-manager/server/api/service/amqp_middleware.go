package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	log "github.com/sirupsen/logrus"

	"github.com/streadway/amqp"
)

const Source = "lamassuiot/device-manager"
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

func (mw *amqpMiddleware) Health(ctx context.Context) (healthy bool) {
	return mw.next.Health(ctx)
}

func (mw *amqpMiddleware) GetStats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error) {
	return mw.next.GetStats(ctx, input)
}

func (mw *amqpMiddleware) CreateDevice(ctx context.Context, input *api.CreateDeviceInput) (output *api.CreateDeviceOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.create", EventPrefix), output.Serialize())
		}

	}()
	return mw.next.CreateDevice(ctx, input)
}

func (mw *amqpMiddleware) UpdateDeviceMetadata(ctx context.Context, input *api.UpdateDeviceMetadataInput) (output *api.UpdateDeviceMetadataOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.update", EventPrefix), output.Serialize())
		}

	}()
	return mw.next.UpdateDeviceMetadata(ctx, input)
}

func (mw *amqpMiddleware) DecommisionDevice(ctx context.Context, input *api.DecommisionDeviceInput) (output *api.DecommisionDeviceOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.decommision", EventPrefix), output.Serialize())
		}
	}()
	return mw.next.DecommisionDevice(ctx, input)
}

func (mw *amqpMiddleware) GetDevices(ctx context.Context, input *api.GetDevicesInput) (*api.GetDevicesOutput, error) {
	return mw.next.GetDevices(ctx, input)
}

func (mw *amqpMiddleware) GetDeviceById(ctx context.Context, input *api.GetDeviceByIdInput) (*api.GetDeviceByIdOutput, error) {
	return mw.next.GetDeviceById(ctx, input)
}

func (mw *amqpMiddleware) IterateDevicesWithPredicate(ctx context.Context, input *api.IterateDevicesWithPredicateInput) (*api.IterateDevicesWithPredicateOutput, error) {
	return mw.next.IterateDevicesWithPredicate(ctx, input)
}

func (mw *amqpMiddleware) AddDeviceSlot(ctx context.Context, input *api.AddDeviceSlotInput) (*api.AddDeviceSlotOutput, error) {
	return mw.next.AddDeviceSlot(ctx, input)
}

func (mw *amqpMiddleware) UpdateActiveCertificateStatus(ctx context.Context, input *api.UpdateActiveCertificateStatusInput) (output *api.UpdateActiveCertificateStatusOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.update", EventPrefix), output.Serialize())
		}

	}()
	return mw.next.UpdateActiveCertificateStatus(ctx, input)
}

func (mw *amqpMiddleware) RotateActiveCertificate(ctx context.Context, input *api.RotateActiveCertificateInput) (output *api.RotateActiveCertificateOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.rotate", EventPrefix), output.Serialize())
		}
	}()
	return mw.next.RotateActiveCertificate(ctx, input)
}

func (mw *amqpMiddleware) RevokeActiveCertificate(ctx context.Context, input *api.RevokeActiveCertificateInput) (output *api.RevokeActiveCertificateOutput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.revoke", EventPrefix), output.Serialize())
		}
	}()
	return mw.next.RevokeActiveCertificate(ctx, input)
}

func (mw *amqpMiddleware) GetDeviceLogs(ctx context.Context, input *api.GetDeviceLogsInput) (*api.GetDeviceLogsOutput, error) {
	return mw.next.GetDeviceLogs(ctx, input)
}

func (mw *amqpMiddleware) IsDMSAuthorizedToEnroll(ctx context.Context, input *api.IsDMSAuthorizedToEnrollInput) (*api.IsDMSAuthorizedToEnrollOutput, error) {
	return mw.next.IsDMSAuthorizedToEnroll(ctx, input)
}

func (mw *amqpMiddleware) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return mw.next.CACerts(ctx, aps)
}

func (mw *amqpMiddleware) Enroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (output *x509.Certificate, err error) {
	defer func() {
		type EnrollLog struct {
			Certificate string `json:"certificate"`
		}
		if err == nil {
			crtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: output.Raw})
			crtB64 := base64.StdEncoding.EncodeToString(crtBytes)
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.enroll", EventPrefix), &EnrollLog{Certificate: crtB64})
		}
	}()
	return mw.next.Enroll(ctx, csr, cert, aps)
}

func (mw *amqpMiddleware) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate) (output *x509.Certificate, err error) {
	defer func() {
		type ReEnrollLog struct {
			Certificate string `json:"certificate"`
		}
		if err == nil {
			crtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: output.Raw})
			crtB64 := base64.StdEncoding.EncodeToString(crtBytes)
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.reenroll", EventPrefix), &ReEnrollLog{Certificate: crtB64})
		}

	}()
	return mw.next.Reenroll(ctx, csr, cert)
}

func (mw *amqpMiddleware) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return mw.next.ServerKeyGen(ctx, csr, cert, aps)
}

func (mw *amqpMiddleware) ForceReenroll(ctx context.Context, input *api.ForceReenrollInput) (output *api.ForceReenrollOtput, err error) {
	defer func() {
		if err == nil {
			mw.sendAMQPMessage(fmt.Sprintf("%s.device.forceReenroll", EventPrefix), output.Serialize())
		}
	}()
	return mw.next.ForceReenroll(ctx, input)
}
