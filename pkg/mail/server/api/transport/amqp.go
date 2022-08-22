package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	amqptransport "github.com/go-kit/kit/transport/amqp"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/streadway/amqp"
)

func AddLoggerToContext(logger log.Logger, otTracer stdopentracing.Tracer) amqptransport.RequestFunc {
	return func(ctx context.Context, pub *amqp.Publishing, del *amqp.Delivery) context.Context {
		span, ctx := stdopentracing.StartSpanFromContextWithTracer(ctx, otTracer, "event-handler")
		logger = log.With(logger, "span_id", span)
		//return context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)
		return ctx
	}
}

func MakeAmqpHandler(s service.Service, logger log.Logger, otTracer stdopentracing.Tracer, amqpServerCaCert string, amqpClientCert string, amqpClientKey string, amqpIp string, amqpPort string) {
	endpoints := endpoint.MakeServerEndpoints(s, otTracer)

	cfg := new(tls.Config)
	cfg.RootCAs = x509.NewCertPool()

	if ca, err := ioutil.ReadFile(amqpServerCaCert); err == nil {
		cfg.RootCAs.AppendCertsFromPEM(ca)
	}

	if cert, err := tls.LoadX509KeyPair(amqpClientCert, amqpClientKey); err == nil {
		cfg.Certificates = append(cfg.Certificates, cert)
	}

	//
	//    !!!!!!!!
	// Esto deberia quitarse --> pruebas para que no valide common name del certificado
	cfg.InsecureSkipVerify = true

	amqpConn, err := amqp.DialTLS("amqps://"+amqpIp+":"+amqpPort, cfg)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Failed to connect to AMQP")
		os.Exit(1)
	}
	defer amqpConn.Close()

	amqpChannel, err := amqpConn.Channel()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Failed to open an AMQP channel")
		os.Exit(1)
	}
	defer amqpChannel.Close()

	lamassuEventsQueue, err := amqpChannel.QueueDeclare("lamassu_events", false, false, false, false, nil)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Failed to create AMQP queue")
		os.Exit(1)
	}

	lamassuEventsMsg, err := amqpChannel.Consume(lamassuEventsQueue.Name, "", true, false, false, false, nil)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Failed to consume AMQP queue")
		os.Exit(1)
	}

	options := []amqptransport.SubscriberOption{
		amqptransport.SubscriberBefore(AddLoggerToContext(logger, otTracer)),
	}

	// AMQP Subscribers
	lamassuEventsSubscriber := amqptransport.NewSubscriber(
		endpoints.EventHandlerEndpoint,
		decodeCloudEventAMQPRequest,
		amqptransport.EncodeJSONResponse,
		append(
			options,
		)...,
	)

	// Handlers
	lamassuEventsHandler := lamassuEventsSubscriber.ServeDelivery(amqpChannel)

	forever := make(chan bool)

	go func() {
		for true {
			select {
			case msg := <-lamassuEventsMsg:
				lamassuEventsHandler(&msg)
			}
		}
	}()

	level.Info(logger).Log("msg", "Waiting Lamassu Requests")

	<-forever
}

func DecodeB64(message string) (string, error) {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	_, err := base64.StdEncoding.Decode(base64Text, []byte(message))
	return string(base64Text), err
}

func decodeCloudEventAMQPRequest(ctx context.Context, delivery *amqp.Delivery) (interface{}, error) {
	/*logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	level.Debug(logger).Log("msg", "Event request received")*/

	var event cloudevents.Event
	err := json.Unmarshal(delivery.Body, &event)
	if err != nil {
		//level.Debug(logger).Log("msg", "decoded event error", "err", err)
		return nil, err
	}
	//level.Debug(logger).Log("msg", "decoded event", "event", event)

	if err != nil {
		return nil, err
	}

	return event, nil
}
