package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	iotplatform "github.com/lamassuiot/lamassuiot/pkg/v3/services/iot/platform"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

var logFormatter = &formatter.Formatter{
	TimestampFormat: "2006-01-02 15:04:05",
	HideKeys:        true,
	FieldsOrder:     []string{"subsystem", "subsystem-provider", "req"},
}

func main() {
	logrus.SetFormatter(logFormatter)
	logrus.SetLevel(logrus.TraceLevel)

	conf, err := config.LoadConfig[config.IoTAWSConfig]()
	if err != nil {
		log.Fatal(err)
	}

	globalLogLevel, err := logrus.ParseLevel(string(conf.Logs.Level))
	if err != nil {
		logrus.Warn("unknown log level. defaulting to 'info' log level")
		globalLogLevel = logrus.InfoLevel
	}
	logrus.SetLevel(globalLogLevel)
	logrus.Infof("global log level set to '%s'", globalLogLevel)

	if !strings.HasPrefix(conf.ID, "aws.") {
		logrus.Fatalf("connector ID must start with 'aws.', got %s", conf.ID)
	}

	logrus.Infof("starting connector with ID %s", conf.ID)

	lSvc := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.Service, "Service")
	lMessage := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.MessagingEngine, "MESSAGING")
	lCAClient := helpers.ConfigureLogger(globalLogLevel, conf.CAClient.LogLevel, "LMS SDK - CA Client")

	caHttpCli, err := clients.BuildHTTPClient(conf.CAClient.HTTPClient, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	caCli := clients.NewHttpCAClient(caHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.Port, conf.CAClient.BasePath))

	amqpSetup, err := messaging.SetupAMQPConnection(lMessage, conf.AMQPConnection)
	if err != nil {
		logrus.Fatal(err)
	}

	err = amqpSetup.SetupAMQPEventSubscriber(conf.ID, []string{"#"})
	if err != nil {
		panic(err)
	}

	svc, err := iotplatform.NewAWSIotPlatformService(iotplatform.AWSIotPlatformServiceBuilder{
		Conf:           conf.AWSSDKConfig,
		Logger:         lSvc,
		BaseHttpClient: http.DefaultClient,
		CACli:          caCli,
		ConnectorID:    conf.ID,
	})
	if err != nil {
		panic(err)
	}

	info, err := svc.GetCloudConfiguration(context.Background())
	if err != nil {
		log.Panic(err)
	}

	fmt.Println(info)

	for {
		select {
		case amqpMessage := <-amqpSetup.Msgs:
			event, err := messaging.ParseCloudEvent(amqpMessage.Body)
			if err != nil {
				logrus.Errorf("Something went wrong: %s", err)
				continue
			}

			eventHandler(lMessage, conf.ID, event, svc)
		}
	}
}

func eventHandler(logger *logrus.Entry, connectorID string, cloudEvent *event.Event, svc iotplatform.IotPlatformService) {
	logError := func(eventID string, eventType string, modelObject string, err error) {
		logger.Errorf("could not decode event '%s' into model '%s' object. Skipping event with ID %s: %s", eventType, modelObject, eventID, err)
	}

	logger.Tracef("incoming cloud event of type: %s", cloudEvent.Type())

	switch cloudEvent.Type() {
	case "ca.create", "ca.import", "ca.update.metadata":
		ca, err := getEventBody[models.CACertificate](cloudEvent)
		if err != nil {
			logError(cloudEvent.ID(), cloudEvent.Type(), "CACertificate", err)
			return
		}

		var registerCA bool
		var ok bool
		meta, ok := ca.Metadata[fmt.Sprintf("lamassu.io/iot-platform-connector/aws/%s/register", connectorID)]
		if !ok {
			logger.Debugf("skipping event of type %s with ID %s. Metadata didn't include key %s", cloudEvent.Type(), cloudEvent.ID(), connectorID)
			return
		}

		if registerCA, ok = meta.(bool); !ok {
			logger.Errorf("skipping event of type %s with ID %s. Invalid metadata content. Got metadata \n%s\n error is: %s", cloudEvent.Type(), cloudEvent.ID(), meta, err)
			return
		}

		if !registerCA {
			// TODO if register CA is false, check if it was already registered. If so, remove registration
			logger.Warnf("skipping event of type %s with ID %s. Register attribute should be true. Got metadata \n%s", cloudEvent.Type(), cloudEvent.ID(), meta)
			return
		}

		//check if CA already registered in AWS
		cas, err := svc.GetRegisteredCAs(context.Background())
		if err != nil {
			logger.Errorf("skipping event of type %s with ID %s. Could not get AWS Registered CAs", cloudEvent.Type(), cloudEvent.ID())
			return
		}

		alreadyRegistered := false
		idx := slices.IndexFunc[*models.CACertificate](cas, func(c *models.CACertificate) bool {
			if c.SerialNumber == ca.SerialNumber {
				return true
			} else {
				return false
			}
		})

		if idx != -1 {
			alreadyRegistered = true
		}

		if !alreadyRegistered {
			logger.Infof("registering CA with SN '%s'", ca.SerialNumber)
			ca, err := svc.RegisterCA(context.Background(), iotplatform.RegisterCAInput{CACertificate: *ca})
			if err != nil {
				logger.Errorf("something went wrong while registering CA with SN '%s' in AWS IoT. Skipping event handling: %s", ca.SerialNumber, err)
				return
			}
		} else {
			logger.Warnf("CA with SN '%s' is already registered in AWS IoT. Skipping registration process", ca.SerialNumber)
		}
	}
}

func getEventBody[E any](cloudEvent *event.Event) (*E, error) {
	var elem *E
	eventDataBytes := cloudEvent.Data()
	err := json.Unmarshal(eventDataBytes, &elem)
	return elem, err
}
