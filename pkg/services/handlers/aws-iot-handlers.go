package handlers

import (
	"context"
	"fmt"
	"slices"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	lms_slices "github.com/lamassuiot/lamassuiot/v2/pkg/helpers/slices"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services/iot"
	"github.com/sirupsen/logrus"
)

func NewAWSIoTEventHandler(l *logrus.Entry, svc iot.AWSCloudConnectorService) *CloudEventHandler {
	return &CloudEventHandler{
		lMessaging: l,
		dispatchMap: map[string]func(*event.Event) error{
			string(models.EventBindDeviceIdentityKey):        func(e *event.Event) error { return handlerWarpper(e, svc, l, bindDeviceIdentityHandler) },
			string(models.EventUpdateDeviceMetadataKey):      func(e *event.Event) error { return handlerWarpper(e, svc, l, updateDeviceMetadataHandler) },
			string(models.EventUpdateCertificateMetadataKey): func(e *event.Event) error { return handlerWarpper(e, svc, l, updateCertificateMetadataHandler) },
			string(models.EventCreateDMSKey):                 func(e *event.Event) error { return handlerWarpper(e, svc, l, createOrUpdateDMSHandler) },
			string(models.EventUpdateDMSKey):                 func(e *event.Event) error { return handlerWarpper(e, svc, l, createOrUpdateDMSHandler) },
			string(models.EventCreateCAKey):                  func(e *event.Event) error { return handlerWarpper(e, svc, l, createOrUpdateCAHandler) },
			string(models.EventImportCAKey):                  func(e *event.Event) error { return handlerWarpper(e, svc, l, createOrUpdateCAHandler) },
			string(models.EventUpdateCAMetadataKey):          func(e *event.Event) error { return handlerWarpper(e, svc, l, createOrUpdateCAHandler) },
		},
	}
}

func handlerWarpper(event *event.Event,
	svc iot.AWSCloudConnectorService,
	logger *logrus.Entry,
	handler func(ctx context.Context, e *event.Event, svc iot.AWSCloudConnectorService, logger *logrus.Entry) error) error {

	ctx := helpers.InitContext()

	logger.Tracef("incoming cloud event: type=%s source=%s id=%s", event.Type(), event.Source(), event.ID())
	if event.Source() == models.AWSIoTSource(svc.ConnectorID) {
		//this prevents processing events generated by this service, and as a consequence of Updating/Creating/Deleting on other Lamassu services,
		//otherwise, the would be a possible infinite loop
		logger.Tracef("dropping cloud event. event source indicates that was originated by this container/service: type=%s source=%s id=%s", event.Type(), event.Source(), event.ID())
		return nil
	}
	return handler(ctx, event, svc, logger)
}

func logDecodeError(logger *logrus.Entry, eventID string, eventType string, modelObject string, err error) {
	logger.Errorf("could not decode event '%s' into model '%s' object. Skipping event with ID %s: %s", eventType, modelObject, eventID, err)
}

func createOrUpdateCAHandler(ctx context.Context, event *event.Event, svc iot.AWSCloudConnectorService, logger *logrus.Entry) error {
	var ca *models.CACertificate
	var err error
	switch event.Type() {
	case string(models.EventUpdateCAMetadataKey):
		updatedCA, err := helpers.GetEventBody[models.UpdateModel[models.CACertificate]](event)
		if err != nil {
			logDecodeError(logger, event.ID(), event.Type(), "UpdateModel CACertificate", err)
			return nil
		}

		ca = &updatedCA.Updated
	default:
		ca, err = helpers.GetEventBody[models.CACertificate](event)
		if err != nil {
			logDecodeError(logger, event.ID(), event.Type(), "CACertificate", err)
			return nil
		}
	}

	var awsIoTCoreCACfg models.IoTAWSCAMetadata
	hasKey, err := helpers.GetMetadataToStruct(ca.Metadata, models.AWSIoTMetadataKey(svc.ConnectorID), &awsIoTCoreCACfg)
	if err != nil {
		err = fmt.Errorf("error while getting %s key: %s", models.AWSIoTMetadataKey(svc.ConnectorID), err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, CA doesn't have %s key", event.Type(), models.AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	_, err = svc.RegisterCA(context.Background(), iot.RegisterCAInput{
		CACertificate:         *ca,
		RegisterConfiguration: awsIoTCoreCACfg,
	})
	if err != nil {
		err = fmt.Errorf("could not register CA %s - %s: %s", ca.ID, ca.Subject.CommonName, err)
		logger.Error(err)
		return err
	}

	return nil
}

func createOrUpdateDMSHandler(ctx context.Context, event *event.Event, svc iot.AWSCloudConnectorService, logger *logrus.Entry) error {
	var dms *models.DMS
	var err error

	isUpdateEvent := false
	var updatedDMS *models.UpdateModel[models.DMS]

	if event.Type() == string(models.EventCreateDMSKey) {
		dms, err = helpers.GetEventBody[models.DMS](event)
		if err != nil {
			logDecodeError(logger, event.ID(), event.Type(), "DMS", err)
			return nil
		}
	} else {
		updatedDMS, err = helpers.GetEventBody[models.UpdateModel[models.DMS]](event)
		if err != nil {
			logDecodeError(logger, event.ID(), event.Type(), "UpdateModel DMS", err)
			return nil
		}

		isUpdateEvent = true
		dms = &updatedDMS.Updated
	}

	var dmsAwsAutomationConfig models.IotAWSDMSMetadata
	hasKey, err := helpers.GetMetadataToStruct(dms.Metadata, models.AWSIoTMetadataKey(svc.ConnectorID), &dmsAwsAutomationConfig)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, DMS doesn't have %s key", event.Type(), models.AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	if dmsAwsAutomationConfig.RegistrationMode == models.JitpAWSIoTRegistrationMode {
		err = svc.RegisterUpdateJITPProvisioner(context.Background(), iot.RegisterUpdateJITPProvisionerInput{
			DMS:           dms,
			AwsJITPConfig: dmsAwsAutomationConfig,
		})
		if err != nil {
			err = fmt.Errorf("something went wrong while registering JITP template for DMS %s: %s", dms.ID, err)
			logger.Error(err)
			return err
		}
	}

	if isUpdateEvent {
		changedManagedCAs := !lms_slices.UnorderedEqualContent(updatedDMS.Previous.Settings.CADistributionSettings.ManagedCAs, updatedDMS.Updated.Settings.CADistributionSettings.ManagedCAs, func(e1, e2 string) bool { return e1 == e2 })
		if changedManagedCAs {
			_, err = svc.DeviceSDK.GetDeviceByDMS(ctx, services.GetDevicesByDMSInput{
				DMSID: dms.ID,
				ListInput: resources.ListInput[models.Device]{
					ExhaustiveRun: true,
					ApplyFunc: func(device models.Device) {
						err = svc.UpdateDeviceShadow(ctx, iot.UpdateDeviceShadowInput{
							DeviceID:               device.ID,
							RemediationActionsType: []models.RemediationActionType{models.RemediationActionUpdateTrustAnchorList},
							DMSIoTAutomationConfig: dmsAwsAutomationConfig,
						})
						if err != nil {
							logger.Errorf("something went wrong while updating %s Thing Shadow: %s", device.ID, err)
							return
						}
					},
				},
			})

			if err != nil {
				err = fmt.Errorf("something went wrong while getting devices By DMS %s: %s", dms.ID, err)
				logger.Error(err)
				return err
			}
		}
	}
	return nil
}

func updateCertificateMetadataHandler(ctx context.Context, event *event.Event, svc iot.AWSCloudConnectorService, logger *logrus.Entry) error {
	certUpdate, err := helpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		logDecodeError(logger, event.ID(), event.Type(), "Certificate", err)
		return nil
	}

	var certUpdatedExpirationDeltas models.CAMetadataMonitoringExpirationDeltas
	var certPreviousExpirationDeltas models.CAMetadataMonitoringExpirationDeltas
	hasKey, err := helpers.GetMetadataToStruct(certUpdate.Updated.Metadata, models.CAMetadataMonitoringExpirationDeltasKey, &certUpdatedExpirationDeltas)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, Certificate doesn't have %s key", event.Type(), models.CAMetadataMonitoringExpirationDeltasKey)
		return nil
	}

	hasKey, err = helpers.GetMetadataToStruct(certUpdate.Previous.Metadata, models.CAMetadataMonitoringExpirationDeltasKey, &certPreviousExpirationDeltas)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, Certificate doesn't have %s key", event.Type(), models.CAMetadataMonitoringExpirationDeltasKey)
		return nil
	}

	preventiveUpdatedIdx := slices.IndexFunc(certUpdatedExpirationDeltas, func(med models.MonitoringExpirationDelta) bool {
		return med.Name == "Preventive"
	})

	preventivePrevIdx := slices.IndexFunc(certPreviousExpirationDeltas, func(med models.MonitoringExpirationDelta) bool {
		return med.Name == "Preventive"
	})

	var attachedBy models.CAAttachedToDevice
	hasKey, err = helpers.GetMetadataToStruct(certUpdate.Updated.Metadata, models.CAAttachedToDeviceKey, &attachedBy)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.CAAttachedToDeviceKey, err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, Certificate doesn't have %s key", event.Type(), models.CAAttachedToDeviceKey)
		return nil
	}

	dms, err := svc.DmsSDK.GetDMSByID(context.Background(), services.GetDMSByIDInput{
		ID: attachedBy.AuthorizedBy.RAID,
	})
	if err != nil {
		err = fmt.Errorf("could not get DMS %s: %s", attachedBy.AuthorizedBy.RAID, err)
		logger.Error(err)
		return err
	}

	var dmsAWSConf models.IotAWSDMSMetadata
	hasKey, err = helpers.GetMetadataToStruct(dms.Metadata, models.AWSIoTMetadataKey(svc.ConnectorID), &dmsAWSConf)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.AWSIoTMetadataKey(svc.ConnectorID), err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, DMS doesn't have %s key", event.Type(), models.AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	if preventiveUpdatedIdx >= 0 && certUpdatedExpirationDeltas[preventiveUpdatedIdx].Triggered {
		// if previously was not triggered (it's the first time) or it did't had a delta defined beforehand
		if (preventivePrevIdx >= 0 && !certPreviousExpirationDeltas[preventivePrevIdx].Triggered) || preventivePrevIdx == -1 {
			err = svc.UpdateDeviceShadow(ctx, iot.UpdateDeviceShadowInput{
				DeviceID:               attachedBy.DeviceID,
				RemediationActionsType: []models.RemediationActionType{models.RemediationActionUpdateCertificate},
				DMSIoTAutomationConfig: dmsAWSConf,
			})
			if err != nil {
				err = fmt.Errorf("something went wrong while updating %s Thing Shadow: %s", attachedBy.DeviceID, err)
				logger.Error(err)
				return err
			}
		}
	}

	return nil
}

func updateDeviceMetadataHandler(ctx context.Context, event *event.Event, svc iot.AWSCloudConnectorService, logger *logrus.Entry) error {
	deviceUpdate, err := helpers.GetEventBody[models.UpdateModel[models.Device]](event)
	if err != nil {
		logDecodeError(logger, event.ID(), event.Type(), "Device", err)
		return nil
	}

	device := deviceUpdate.Updated
	var deviceMetaAWS models.DeviceAWSMetadata
	hasKey, err := helpers.GetMetadataToStruct(device.Metadata, models.AWSIoTMetadataKey(svc.ConnectorID), &deviceMetaAWS)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.AWSIoTMetadataKey(svc.ConnectorID), err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, Device doesn't have %s key", event.Type(), models.AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	dms, err := svc.DmsSDK.GetDMSByID(context.Background(), services.GetDMSByIDInput{
		ID: device.DMSOwner,
	})
	if err != nil {
		err = fmt.Errorf("could not get DMS %s: %s", device.DMSOwner, err)
		logger.Error(err)
		return err
	}

	var dmsAWSConf models.IotAWSDMSMetadata
	hasKey, err = helpers.GetMetadataToStruct(dms.Metadata, models.AWSIoTMetadataKey(svc.ConnectorID), &dmsAWSConf)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.AWSIoTMetadataKey(svc.ConnectorID), err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, DMS doesn't have %s key", event.Type(), models.AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	if len(deviceMetaAWS.Actions) > 0 {
		err = svc.UpdateDeviceShadow(ctx, iot.UpdateDeviceShadowInput{
			DeviceID:               device.ID,
			RemediationActionsType: deviceMetaAWS.Actions,
			DMSIoTAutomationConfig: dmsAWSConf,
		})
		if err != nil {
			err = fmt.Errorf("something went wrong while updating %s Thing Shadow: %s", device.ID, err)
			logger.Error(err)
			return err
		}
	}

	return nil
}

func bindDeviceIdentityHandler(ctx context.Context, event *event.Event, svc iot.AWSCloudConnectorService, logger *logrus.Entry) error {
	bindEvent, err := helpers.GetEventBody[models.BindIdentityToDeviceOutput](event)
	if err != nil {
		logDecodeError(logger, event.ID(), event.Type(), "Certificate", err)
		return nil
	}

	dms := bindEvent.DMS

	var dmsAwsAutomationConfig models.IotAWSDMSMetadata
	hasKey, err := helpers.GetMetadataToStruct(dms.Metadata, models.AWSIoTMetadataKey(svc.ConnectorID), &dmsAwsAutomationConfig)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
		logger.Error(err)
		return err
	}

	if !hasKey {
		logrus.Warnf("skipping event %s, DMS doesn't have %s key", event.Type(), models.AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	if dmsAwsAutomationConfig.RegistrationMode == models.AutomaticAWSIoTRegistrationMode {
		thingID := bindEvent.Certificate.Subject.CommonName
		logrus.Infof("registering %s device", thingID)
		err = svc.RegisterAndAttachThing(ctx, iot.RegisterAndAttachThingInput{
			DeviceID:               thingID,
			DMSIoTAutomationConfig: dmsAwsAutomationConfig,
			BindedIdentity:         *bindEvent,
		})
		if err != nil {
			err = fmt.Errorf("something went wrong while registering device %s: %s", thingID, err)
			logger.Error(err)
			return err
		}
	}

	return nil
}
