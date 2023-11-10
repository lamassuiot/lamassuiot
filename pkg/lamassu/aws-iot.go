package lamassu

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services/iot"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

func AssembleAWSIoTManagerService(conf config.IotAWS, caService services.CAService, dmsService services.DMSManagerService, deviceService services.DeviceManagerService) (*iot.AWSCloudConnectorService, error) {
	file, _ := os.OpenFile("aws.logs", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	lSvc := helpers.ConfigureLogger(conf.Logs.Level, "Service")
	lSvc.Logger.SetOutput(io.MultiWriter(os.Stdout, file))
	lMessaging := helpers.ConfigureLogger(conf.BaseConfig.AMQPConnection.LogLevel, "Messaging")

	awsCfg, err := config.GetAwsSdkConfig(conf.AWSSDKConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get aws config: %s", err)
	}

	awsConnectorSvc, err := iot.NewAWSCloudConnectorServiceService(iot.AWSCloudConnectorBuilder{
		Conf:        *awsCfg,
		Logger:      lSvc,
		ConnectorID: conf.ConnectorID,
		CaSDK:       caService,
		DmsSDK:      dmsService,
		DeviceSDK:   deviceService,
	})
	if err != nil {
		log.Fatal(err)
	}

	amqpSetup, err := messaging.SetupAMQPConnection(lMessaging, conf.AMQPConnection)
	if err != nil {
		return nil, err
	}

	err = amqpSetup.SetupAMQPEventSubscriber("cloud-connector", []string{"#"})
	if err != nil {
		return nil, err
	}

	go func() {
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
	}()

	return awsConnectorSvc, nil
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

		preventiveIdx := slices.IndexFunc(certExpirationDeltas, func(med models.MonitoringExpirationDelta) bool {
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
			ID: attachedBy.AuthorizedBy.RAID,
		})
		if err != nil {
			logger.Errorf("could not get DMS %s: %s", attachedBy.AuthorizedBy.RAID, err)
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
			updatedCA, err := getEventBody[models.UpdateModel[models.CACertificate]](cloudEvent)
			if err != nil {
				logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "UpdateModel CACertificate", err)
				return
			}

			ca = &updatedCA.Updated
		default:
			ca, err = getEventBody[models.CACertificate](cloudEvent)
			if err != nil {
				logDecodeError(cloudEvent.ID(), cloudEvent.Type(), "CACertificate", err)
				return
			}
		}

		var awsIoTCoreCACfg models.IoTAWSCAMetadata
		hasKey, err := helpers.GetMetadataToStruct(ca.Metadata, models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID), &awsIoTCoreCACfg)
		if err != nil {
			logrus.Errorf("error while getting %s key: %s", models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID), err)
			return
		}

		if !hasKey {
			logrus.Warnf("skipping event %s, CA doesn't have %s key", cloudEvent.Type(), models.AWSIoTMetadataKey(awsConnectorSvc.ConnectorID))
			return
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
