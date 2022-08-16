package service

// import (
// 	"context"
// 	"crypto/x509"
// 	"encoding/json"
// 	"fmt"
// 	"time"

// 	cloudevents "github.com/cloudevents/sdk-go/v2"
// 	"github.com/cloudevents/sdk-go/v2/event"
// 	"github.com/go-kit/kit/log"
// 	"github.com/go-kit/kit/log/level"
// 	"github.com/jakehl/goid"
// 	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
//
// 	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
// 	"github.com/streadway/amqp"
// )

// func CreateEvent(ctx context.Context, version string, source string, types string) event.Event {
// 	// trace_id := opentracing.SpanFromContext(ctx)
// 	trace_id := goid.NewV4UUID().String()
// 	event := cloudevents.NewEvent()
// 	event.SetSpecVersion(version)
// 	event.SetSource(source)
// 	event.SetType(types)
// 	event.SetTime(time.Now())
// 	event.SetID(fmt.Sprintf("%s", trace_id))
// 	return event
// }

// type amqpMiddleware struct {
// 	amqpChannel *amqp.Channel
// 	logger      log.Logger
// 	next        Service
// }

// func NewAmqpMiddleware(channel *amqp.Channel, logger log.Logger) Middleware {
// 	return func(next Service) Service {
// 		return &amqpMiddleware{
// 			amqpChannel: channel,
// 			logger:      logger,
// 			next:        next,
// 		}
// 	}
// }

// func (mw *amqpMiddleware) GetEngineProviderInfo() (config api.EngineProviderInfo) {
// 	defer func(begin time.Time) {

// 	}(time.Now())
// 	return mw.next.GetEngineProviderInfo()
// }

// func (mw *amqpMiddleware) Health() bool {
// 	defer func(begin time.Time) {

// 	}(time.Now())
// 	return mw.next.Health(ctx)
// }

// func (mw *amqpMiddleware) Stats(input *api.GetStatsInput) (output *api.GetStatsOutput, err error) {
// 	defer func(begin time.Time) {

// 	}(time.Now())
// 	return mw.next.Stats(ctx)
// }

// func (mw *amqpMiddleware) CreateCA(input *api.CreateCAInput) (out *api.CreateCAOutput, err error) {
// 	defer func(begin time.Time) {
// 		if err == nil {
// 			event := CreateEvent(ctx, "1.0", "lamassu/ca", "io.lamassu.ca.create")
// 			event.SetData(cloudevents.ApplicationJSON)

// 			mw.sendAMQPMessage(event)
// 		}
// 	}(time.Now())

// 	return mw.next.CreateCA(ctx, caType, caName, privateKeyMetadata, subject, caTTL, enrollerTTL)
// }

// func (mw *amqpMiddleware) GetCAs(ctx context.Context, caType dto.CAType, queryparameters filters.QueryParameters) (CAs []dto.Cert, total int, err error) {
// 	defer func(begin time.Time) {

// 	}(time.Now())

// 	return mw.next.GetCAs(ctx, caType, queryparameters)
// }

// func (mw *amqpMiddleware) ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL int) (createdCa dto.Cert, err error) {
// 	defer func(begin time.Time) {
// 		if err == nil {
// 			event := CreateEvent(ctx, "1.0", "lamassu/ca", "io.lamassu.ca.import")
// 			type ImportCAEvent struct {
// 				Name         string `json:"name"`
// 				SerialNumber string `json:"serial_number"`
// 				Cert         string `json:"cert"`
// 			}
// 			event.SetData(cloudevents.ApplicationJSON, ImportCAEvent{
// 				Name:         createdCa.Name,
// 				SerialNumber: createdCa.SerialNumber,
// 				Cert:         createdCa.CertContent.CerificateBase64,
// 			})

// 			mw.sendAMQPMessage(event)
// 		}
// 	}(time.Now())
// 	return mw.next.ImportCA(ctx, caType, caName, certificate, privateKey, enrollerTTL)
// }

// func (mw *amqpMiddleware) RevokeCA(ctx context.Context, caType dto.CAType, CA string) (err error) {
// 	defer func(begin time.Time) {
// 		if err == nil {
// 			event := CreateEvent(ctx, "1.0", "lamassu/ca", "io.lamassu.ca.update")
// 			type RevokeCAEvent struct {
// 				Name   string `json:"name"`
// 				Status string `json:"status"`
// 			}
// 			event.SetData(cloudevents.ApplicationJSON, RevokeCAEvent{
// 				Name:   CA,
// 				Status: "",
// 			})

// 			mw.sendAMQPMessage(event)
// 		}
// 	}(time.Now())

// 	return mw.next.RevokeCA(ctx, caType, CA)
// }

// func (mw *amqpMiddleware) GetIssuedCerts(ctx context.Context, caType dto.CAType, caName string, queryParameters filters.QueryParameters) (certs []dto.Cert, length int, err error) {
// 	defer func(begin time.Time) {

// 	}(time.Now())
// 	return mw.next.GetIssuedCerts(ctx, caType, caName, queryParameters)
// }
// func (mw *amqpMiddleware) GetCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (cert dto.Cert, err error) {
// 	defer func(begin time.Time) {

// 	}(time.Now())

// 	return mw.next.GetCert(ctx, caType, caName, serialNumber)
// }

// func (mw *amqpMiddleware) DeleteCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (err error) {
// 	defer func(begin time.Time) {
// 		if err == nil {
// 			event := CreateEvent(ctx, "1.0", "lamassu/ca", "io.lamassu.cert.update")
// 			type DeleteCertEvent struct {
// 				Name         string `json:"name"`
// 				SerialNumber string `json:"serial_number"`
// 				Status       string `json:"status"`
// 			}
// 			event.SetData(cloudevents.ApplicationJSON, DeleteCertEvent{
// 				Name:         caName,
// 				SerialNumber: serialNumber,
// 				Status:       "REVOKED",
// 			})
// 			mw.sendAMQPMessage(event)
// 		}
// 	}(time.Now())
// 	return mw.next.DeleteCert(ctx, caType, caName, serialNumber)
// }

// func (mw *amqpMiddleware) SignCertificate(ctx context.Context, caType dto.CAType, caName string, csr x509.CertificateRequest, signVerbatim bool, cn string) (certs dto.SignResponse, err error) {
// 	defer func(begin time.Time) {

// 	}(time.Now())
// 	return mw.next.SignCertificate(ctx, caType, caName, csr, signVerbatim, cn)
// }

// func (mw *amqpMiddleware) sendAMQPMessage(event cloudevents.Event) {
// 	eventBytes, marshalErr := json.Marshal(event)
// 	if marshalErr != nil {
// 		level.Error(mw.logger).Log("msg", "Error while serializing event", "err", marshalErr)
// 	}

// 	amqpErr := mw.amqpChannel.Publish("", "lamassu_events", false, false, amqp.Publishing{
// 		ContentType: "text/json",
// 		Body:        []byte(eventBytes),
// 	})
// 	if amqpErr != nil {
// 		level.Error(mw.logger).Log("msg", "Error while publishing to AMQP queue", "err", amqpErr)
// 	}
// }
