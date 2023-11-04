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
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services/iot"
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

	conf, err := config.LoadConfig[config.IotAWS]()
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

	lSvc := helpers.ConfigureLogger(conf.Logs.Level, "Service")
	// lHttp := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.HttpTransport, "HTTP Server")
	lMessaging := helpers.ConfigureLogger(conf.AMQPConnection.LogLevel, "Messaging")

	lDMSClient := helpers.ConfigureLogger(conf.DMSManagerClient.LogLevel, "LMS SDK - DMS Client")
	lDeviceClient := helpers.ConfigureLogger(conf.DevManagerClient.LogLevel, "LMS SDK - Device Client")
	lCAClient := helpers.ConfigureLogger(conf.CAClient.LogLevel, "LMS SDK - CA Client")

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

	awsConnectorSvc, err := iot.NewAWSCloudConnectorServiceService(iot.AWSCloudConnectorBuilder{
		Conf:        config.GetAwsSdkConfig(conf.AWSSDKConfig),
		Logger:      lSvc,
		ConnectorID: conf.ConnectorID,
		CaSDK:       caSDK,
		DmsSDK:      dmsSDK,
		DeviceSDK:   deviceSDK,
	})
	if err != nil {
		log.Fatal(err)
	}

	amqpSetup, err := messaging.SetupAMQPConnection(lMessaging, conf.AMQPConnection)
	if err != nil {
		logrus.Fatal(err)
	}

	err = amqpSetup.SetupAMQPEventSubscriber("cloud-connector", []string{"#"})
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case amqpMessage := <-amqpSetup.Msgs:
			event, err := messaging.ParseCloudEvent(amqpMessage.Body)
			if err != nil {
				logrus.Errorf("Something went wrong: %s", err)
				continue
			}

			eventHandler(lMessaging, event, *awsConnectorSvc)
		}
	}

	forever := make(chan struct{})
	<-forever
}

func eventHandler(logger *logrus.Entry, cloudEvent *event.Event, awsConnectorSvc iot.AWSCloudConnectorService) {
	logDecodeError := func(eventID string, eventType string, modelObject string, err error) {
		logger.Errorf("could not decode event '%s' into model '%s' object. Skipping event with ID %s: %s", eventType, modelObject, eventID, err)
	}

	logger.Tracef("incoming cloud event of type: %s", cloudEvent.Type())

	switch cloudEvent.Type() {
	case string(models.EventUpdateCertificateMetadataKey):
		certUpdate, err := getEventBody[models.UpdateModel[models.Certificate]](cloudEvent)
		if err != nil {
			logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "Certificate", err)
			return
		}

		cert := certUpdate.Updated

		var certExpirationDeltas models.CAMetadataMonitoringExpirationDeltas
		hasKey, err := helpers.GetMetadataToStruct(cert.Metadata, models.CAMetadataMonitoringExpirationDeltasKey, certExpirationDeltas)
		if err != nil {
			logger.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
			return
		}

		if !hasKey {
			logrus.Warnf("skipping event %s, Certificate doesn't have %s key", cloudEvent.Type(), models.CAMetadataMonitoringExpirationDeltasKey)
			return
		}

		preventiveIdx := slices.IndexFunc[models.MonitoringExpirationDelta](certExpirationDeltas, func(med models.MonitoringExpirationDelta) bool {
			if med.Name == "Preventive" {
				return true
			}
			return false
		})

		var attachedBy models.CAAttachedToDevice
		hasKey, err = helpers.GetMetadataToStruct(cert.Metadata, models.CAAttachedToDeviceKey, attachedBy)
		if err != nil {
			logger.Errorf("could not decode metadata with key %s: %s", models.CAAttachedToDeviceKey, err)
			return
		}

		if !hasKey {
			logrus.Warnf("skipping event %s, Certificate doesn't have %s key", cloudEvent.Type(), models.CAAttachedToDeviceKey)
			return
		}

		dms, err := awsConnectorSvc.DmsSDK.GetDMSByID(services.GetDMSByIDInput{
			ID: attachedBy.RAID,
		})
		if err != nil {
			logger.Errorf("could not get DMS %s: %s", attachedBy.RAID, err)
			return
		}

		var dmsAWSConf models.IotAWSDMSMetadata
		hasKey, err = helpers.GetMetadataToStruct(dms.Metadata, models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID), dmsAWSConf)
		if err != nil {
			logger.Errorf("could not decode metadata with key %s: %s", models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID), err)
			return
		}

		if !hasKey {
			logrus.Warnf("skipping event %s, DMS doesn't have %s key", cloudEvent.Type(), models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID))
			return
		}

		if preventiveIdx >= 0 && certExpirationDeltas[preventiveIdx].Triggered {
			err = awsConnectorSvc.UpdateDeviceShadow(iot.UpdateDeviceShadowInput{
				DeviceID:               cert.Subject.CommonName,
				RemediationActionType:  models.RemediationActionUpdateCertificate,
				DMSIoTAutomationConfig: dmsAWSConf,
			})
			if err != nil {
				logger.Errorf("something went wrong while updating %s Thing Shadow: %s", attachedBy.DeviceID, err)
				return
			}
		}

	case string(models.EventCreateDMSKey), string(models.EventUpdateDMSMetadataKey):
		var dms *models.DMS
		var err error
		if cloudEvent.Type() == string(models.EventCreateDMSKey) {
			dms, err = getEventBody[models.DMS](cloudEvent)
			if err != nil {
				logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "DMS", err)
				return
			}
		} else {
			updatedDMS, err := getEventBody[models.UpdateModel[models.DMS]](cloudEvent)
			if err != nil {
				logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "UpdateModel DMS", err)
				return
			}

			dms = &updatedDMS.Updated
		}

		var dmsAwsAutomationConfig models.IotAWSDMSMetadata
		hasKey, err := helpers.GetMetadataToStruct(dms.Metadata, models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID), dmsAwsAutomationConfig)
		if err != nil {
			logger.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
			return
		}

		if !hasKey {
			logrus.Warnf("skipping event %s, DMS doesn't have %s key", cloudEvent.Type(), models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID))
			return
		}

		awsConnectorSvc.RegisterUpdateJITPProvisioner(context.Background(), iot.RegisterUpdateJITPProvisionerInput{
			DMS: dms,
		})

	case string(models.EventCreateCAKey), string(models.EventImportCAKey), string(models.EventUpdateCAMetadataKey):
		var ca *models.CACertificate
		var err error
		switch cloudEvent.Type() {
		case string(models.EventUpdateCAMetadataKey):
			ca, err = getEventBody[models.CACertificate](cloudEvent)
			if err != nil {
				logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "CACertificate", err)
				return
			}
		default:
			updatedCA, err := getEventBody[models.UpdateModel[models.CACertificate]](cloudEvent)
			if err != nil {
				logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "UpdateModel CACertificate", err)
				return
			}

			ca = &updatedCA.Updated
		}

		var awsIoTCoreCACfg models.IoTAWSCAMetadata
		hasKey, err := helpers.GetMetadataToStruct(ca.Metadata, models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID), &awsIoTCoreCACfg)
		if err != nil {
			logrus.Errorf("error while getting %s key: %s", models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID), err)
			return
		}

		if !hasKey {
			logrus.Warnf("skipping event %s, CA doesn't have %s key", cloudEvent.Type(), models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID))
		}

		awsConnectorSvc.RegisterCA(context.Background(), iot.RegisterCAInput{
			CACertificate:         *ca,
			RegisterConfiguration: awsIoTCoreCACfg,
		})
	}
}

func getEventBody[E any](cloudEvent *event.Event) (*E, error) {
	var elem *E
	eventDataBytes := cloudEvent.Data()
	err := json.Unmarshal(eventDataBytes, &elem)
	return elem, err
}
