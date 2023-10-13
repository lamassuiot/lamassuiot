package iot

import (
	"encoding/json"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

type IotDeviceLifeCycleAutomationServiceProvider[E any] interface {
	UpdateDeviceDigitalTwin(input UpdateDeviceDigitalTwinInput[E]) error
}
type UpdateDeviceDigitalTwinInput[E any] struct {
	DeviceID               string
	BodyMessage            []byte
	DMSIoTAutomationConfig E
}

type IotDeviceLifeCycleAutomationService interface {
	UpdateDigitalTwin(input UpdateDigitalTwinInput) error
}

type UpdateDigitalTwinInput struct {
	DeviceID    string
	TriggeredBy string
	Action      models.RemediationActionType
	Remediated  bool
}

type automationProviderInstance[E any] struct {
	DMSAutomationModel E
	Provider           IotDeviceLifeCycleAutomationServiceProvider[E]
}
type IotDeviceLifeCycleAutomationImpl struct {
	lamassuInstanceURL  string
	deviceSDK           services.DeviceManagerService
	dmsSDK              services.DMSManagerService
	automationProviders map[string]automationProviderInstance[any]
}

func (svc *IotDeviceLifeCycleAutomationImpl) UpdateDigitalTwin(input UpdateDigitalTwinInput) error {
	device, err := svc.deviceSDK.GetDeviceByID(services.GetDeviceByIDInput{
		ID: input.DeviceID,
	})
	if err != nil {
		logrus.Errorf("could not get device %s: %s", input.DeviceID, err)
		return err
	}

	dms, err := svc.dmsSDK.GetDMSByID(services.GetDMSByIDInput{
		ID: device.DMSOwnerID,
	})
	if err != nil {
		logrus.Errorf("could not get DMS %s: %s", device.DMSOwnerID, err)
		return err
	}

	for connectorID, digitalTwinProvider := range svc.automationProviders {
		dmsAutomationCfg := digitalTwinProvider.DMSAutomationModel
		hasKey, err := helpers.GetMetadataToStruct(dms.Metadata, models.DeviceMetadataIotAutomationKey(connectorID), &dmsAutomationCfg)
		if err != nil {
			logrus.Errorf("could not get connector %s metadata: %s", dms.ID, err)
			return nil
		}
		if !hasKey {
			logrus.Warnf("connector %s is not configured for this DMS", dms.ID)
			return nil
		}

		logrus.Infof("DMS %s is configured with IoT Automation", dms.ID)

		deviceMeta := device.Metadata
		var deviceAutomationMeta models.RemediateTracker
		hasKey, err = helpers.GetMetadataToStruct(deviceMeta, models.DeviceMetadataIotAutomationKey(connectorID), &deviceAutomationMeta)
		if err != nil {
			logrus.Errorf("could not get device %s metadata: %s", device.ID, err)
			return nil
		}

		var prevDevDTwinState models.DigitalTwinIdentityState

		if !hasKey {
			logrus.Infof("device %s has no automation metadata key for this connector. Will create Metadata Key %s", device.ID, models.DeviceMetadataIotAutomationKey(connectorID))
			deviceAutomationMeta = models.RemediateTracker{
				ActiveDigitalTwinIdentityState: models.DigitalTwinIdentityState{},
				Historical:                     []*models.DigitalTwinActionTracker{},
			}
		} else {
			logrus.Infof("device %s has automation metadata key for this connector. Checking if remediation update is required")
		}

		prevDevDTwinState = deviceAutomationMeta.ActiveDigitalTwinIdentityState

		if _, hasKey := deviceAutomationMeta.ActiveDigitalTwinIdentityState[input.Action]; !hasKey {
			logrus.Infof("device %s has no automation %s remediation action. Will create active remediation action", device.ID, input.Action)
			prevDevDTwinState[input.Action] = &models.DigitalTwinActionTracker{
				CreatedAt: time.Now(),
			}
		} else {
			logrus.Infof("device %s already has %s remediation action", device.ID, input.Action)
		}

		if prevDevDTwinState[input.Action].Remediated == input.Remediated {
			logrus.Debugf("requested remediation to be set to %t but device meta already reports in %t", input.Remediated, prevDevDTwinState[input.Action].Remediated)
			logrus.Infof("device %s does not require an update on %s remediation action. Doing nothing")
			return nil
		}

		logrus.Infof("device %s require an update on %s remediation action")
		logrus.Debugf("requested remediation to be set to %t but device meta already reports in %t", input.Remediated, prevDevDTwinState[input.Action].Remediated)
		prevDevDTwinState[input.Action] = &models.DigitalTwinActionTracker{
			TriggeredBy: input.TriggeredBy,
			Remediated:  input.Remediated,
			State: models.DigitalTwinRemediationActionState{
				RemediationType: input.Action,
				LamassuInstance: models.LamassuConfiguration{
					URL:   svc.lamassuInstanceURL,
					DMSID: dms.ID,
				},
			},
		}

		if input.Remediated {
			remediationActionToClose := prevDevDTwinState[input.Action]
			remediationActionToClose.RemediatedAt = time.Now()

			deviceAutomationMeta.Historical = append(deviceAutomationMeta.Historical, remediationActionToClose)
			delete(prevDevDTwinState, input.Action)
		}

		deviceAutomationMeta.ActiveDigitalTwinIdentityState = prevDevDTwinState

		shadowPayloadBytes, err := json.Marshal(prevDevDTwinState)
		if err != nil {
			logrus.Errorf("could not encode DeviceDigitalTwinState struct: %s", err)
			return err
		}

		digitalTwinProvider.Provider.UpdateDeviceDigitalTwin(UpdateDeviceDigitalTwinInput[any]{
			DeviceID:               input.DeviceID,
			BodyMessage:            shadowPayloadBytes,
			DMSIoTAutomationConfig: dmsAutomationCfg,
		})

		logrus.Infof("updated shadow for thing %s with %s action", device.ID, input.Action)

		deviceMeta[models.DeviceMetadataIotAutomationKey(connectorID)] = deviceAutomationMeta

		_, err = svc.deviceSDK.UpdateDeviceMetadata(services.UpdateDeviceMetadataInput{
			ID:       input.DeviceID,
			Metadata: deviceMeta,
		})

		if err != nil {
			logrus.Errorf("could not update device metadata: %s", err)
			return err
		}

		return nil
	}

	return nil
}
