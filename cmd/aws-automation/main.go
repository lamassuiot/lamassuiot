package main

import (
	"context"
	"encoding/json"
	"fmt"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	iotautomation "github.com/lamassuiot/lamassuiot/pkg/v3/services/iot/automation"
	iotplatform "github.com/lamassuiot/lamassuiot/pkg/v3/services/iot/platform"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

var (
	version   string = "v0"    // api version
	sha1ver   string = "-"     // sha1 revision used to build the program
	buildTime string = "devTS" // when the executable was built
)

var logFormatter = &formatter.Formatter{
	TimestampFormat: "2006-01-02 15:04:05",
	HideKeys:        true,
	FieldsOrder:     []string{"subsystem", "subsystem-provider", "req"},
}

func main() {
	log.SetFormatter(logFormatter)

	log.Infof("starting api: version=%s buildTime=%s sha1ver=%s", version, buildTime, sha1ver)

	conf, err := config.LoadConfig[config.IotAutomation]()
	if err != nil {
		log.Fatal(err)
	}

	globalLogLevel, err := log.ParseLevel(string(conf.Logs.Level))
	if err != nil {
		log.Warn("unknown log level. defaulting to 'info' log level")
		globalLogLevel = log.InfoLevel
	}
	log.SetLevel(globalLogLevel)
	log.Infof("global log level set to '%s'", globalLogLevel)

	lSvc := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.Service, "Service")
	// lHttp := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.HttpTransport, "HTTP Server")
	lMessaging := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.MessagingEngine, "Messaging")

	lDMSClient := helpers.ConfigureLogger(globalLogLevel, conf.DMSManagerClient.LogLevel, "LMS SDK - DMS Client")
	lDeviceClient := helpers.ConfigureLogger(globalLogLevel, conf.DevManagerClient.LogLevel, "LMS SDK - Device Client")
	lCAClient := helpers.ConfigureLogger(globalLogLevel, conf.CAClient.LogLevel, "LMS SDK - CA Client")

	dmsHttpCli, err := clients.BuildHTTPClient(conf.DMSManagerClient.HTTPClient, lDMSClient)
	if err != nil {
		log.Fatalf("could not build HTTP DMS Manager Client: %s", err)
	}

	deviceHttpCli, err := clients.BuildHTTPClient(conf.DevManagerClient.HTTPClient, lDeviceClient)
	if err != nil {
		log.Fatalf("could not build HTTP Device Client: %s", err)
	}

	caHttpCli, err := clients.BuildHTTPClient(conf.CAClient.HTTPClient, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	dmsSDK := clients.NewHttpDMSManagerClient(dmsHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.DMSManagerClient.Protocol, conf.DMSManagerClient.Hostname, conf.DMSManagerClient.Port, conf.DMSManagerClient.BasePath))
	deviceSDK := clients.NewHttpDeviceManagerClient(deviceHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.DevManagerClient.Protocol, conf.DevManagerClient.Hostname, conf.DevManagerClient.Port, conf.DevManagerClient.BasePath))
	caSDK := clients.NewHttpCAClient(caHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.Port, conf.CAClient.BasePath))

	automationProviders := map[string]iotautomation.AutomationProviderInstance{}
	for _, awsProvider := range conf.Providers.AWS {
		awsConf := config.GetAwsSdkConfig(awsProvider.AWSSDKConfig)

		awsAuto, err := iotautomation.NewAWSIotAutomationService(iotautomation.AWSIotAutomationBuilder{
			Conf:   awsConf,
			Logger: lSvc,
		})
		if err != nil {
			log.Fatalf("could not build connector %s: %s", awsProvider.ConnectorID, err)
		}

		automationProviders[awsProvider.ConnectorID] = iotautomation.AutomationProviderInstance{
			Provider: awsAuto,
		}
	}

	platformProviders := map[string]iotplatform.IotPlatformService{}
	for _, awsProvider := range conf.Providers.AWS {
		awsConf := config.GetAwsSdkConfig(awsProvider.AWSSDKConfig)

		awsPlatform, err := iotplatform.NewAWSIotPlatformService(iotplatform.AWSIotPlatformServiceBuilder{
			Conf:        awsConf,
			Logger:      lSvc,
			ConnectorID: awsProvider.ConnectorID,
			CACli:       caSDK,
		})
		if err != nil {
			log.Fatalf("could not build connector %s: %s", awsProvider.ConnectorID, err)
		}

		platformProviders[awsProvider.ConnectorID] = awsPlatform
	}

	automationSvc := iotautomation.NewIotDeviceLifeCycleAutomationService(iotautomation.IotDeviceLifeCycleAutomationServiceBuilder{
		Logger:              lSvc,
		DeviceSDK:           deviceSDK,
		DmsSDK:              dmsSDK,
		LamassuInstanceURL:  conf.LamassuInstanceURL,
		AutomationProviders: automationProviders,
	})

	platformSvc := iotplatform.NewIotPlatform(iotplatform.IotPlatformBuilder{
		PlatformProviders: platformProviders,
	})

	amqpSetup, err := messaging.SetupAMQPConnection(lMessaging, conf.AMQPConnection)
	if err != nil {
		logrus.Fatal(err)
	}

	err = amqpSetup.SetupAMQPEventSubscriber("cloud-connector", []string{"#"})
	if err != nil {
		panic(err)
	}

	for {
		select {
		case amqpMessage := <-amqpSetup.Msgs:
			event, err := messaging.ParseCloudEvent(amqpMessage.Body)
			if err != nil {
				logrus.Errorf("Something went wrong: %s", err)
				continue
			}

			eventHandler(lMessaging, event, automationSvc, platformSvc)
		}
	}

	forever := make(chan struct{})
	<-forever
}

func eventHandler(logger *logrus.Entry, cloudEvent *event.Event, automationSvc iotautomation.IotDeviceLifeCycleAutomationService, platformSvc iotplatform.IotPlatformService) {
	logDecodeError := func(eventID string, eventType string, modelObject string, err error) {
		logger.Errorf("could not decode event '%s' into model '%s' object. Skipping event with ID %s: %s", eventType, modelObject, eventID, err)
	}

	logger.Tracef("incoming cloud event of type: %s", cloudEvent.Type())

	switch cloudEvent.Type() {
	case string(models.EventUpdateCertificateMetadata):
		cert, err := getEventBody[models.Certificate](cloudEvent)
		if err != nil {
			logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "Certificate", err)
			return
		}

		var certExpirationDeltas models.CAMetadataMonitoringExpirationDeltas
		hasKey, err := helpers.GetMetadataToStruct(cert.Metadata, models.CAMetadataMonitoringExpirationDeltasKey, certExpirationDeltas)
		if err != nil {
			logger.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
			return
		}

		if !hasKey {
			return
		}

		preventiveIdx := slices.IndexFunc[models.MonitoringExpirationDelta](certExpirationDeltas, func(med models.MonitoringExpirationDelta) bool {
			if med.Name == "Preventive" {
				return true
			}
			return false
		})

		if preventiveIdx >= 0 && certExpirationDeltas[preventiveIdx].Triggered {
			automationSvc.UpdateDigitalTwin(iotautomation.UpdateDigitalTwinInput{
				DeviceID:    cert.Subject.CommonName,
				TriggeredBy: fmt.Sprintf("CloudEvent-PreventiveExpirationDate-%s", cloudEvent.ID()),
				Action:      models.RemediationActionUpdateCertificate,
				Remediated:  false,
			})
		}

	case string(models.EventCreateDMS), string(models.EventUpdateDMSMetadata):
		dms, err := getEventBody[models.DMS](cloudEvent)
		if err != nil {
			logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "DMS", err)
			return
		}

		platformSvc.RegisterUpdateJITPProvisioner(context.Background(), iotplatform.RegisterJITPProvisionerInput{
			DMS: dms,
		})

	case string(models.EventCreateCA), string(models.EventImportCA), string(models.EventUpdateCAMetadata):
		ca, err := getEventBody[models.CACertificate](cloudEvent)
		if err != nil {
			logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "CACertificate", err)
			return
		}

		platformSvc.RegisterCA(context.Background(), iotplatform.RegisterCAInput{
			CACertificate: *ca,
		})
	}
}

func getEventBody[E any](cloudEvent *event.Event) (*E, error) {
	var elem *E
	eventDataBytes := cloudEvent.Data()
	err := json.Unmarshal(eventDataBytes, &elem)
	return elem, err
}
