package iotautomation

import (
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

var lIotAuto *logrus.Entry

type IotDeviceAutomationJobServiceProvider interface {
	CreateDeviceDigitalTwinJob(input CreateDeviceDigitalTwinJobInput) error
}
type CreateDeviceDigitalTwinJobInput struct {
	DeviceID               string
	Action                 models.DigitalTwinRemediationActionState
	DMSIoTAutomationConfig any
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

type AutomationProviderInstance struct {
	Provider IotDeviceAutomationJobServiceProvider
}
type IotDeviceLifeCycleAutomationImpl struct {
	lamassuInstanceURL  string
	deviceSDK           services.DeviceManagerService
	dmsSDK              services.DMSManagerService
	automationProviders map[string]AutomationProviderInstance
}

type IotDeviceLifeCycleAutomationServiceBuilder struct {
	LamassuInstanceURL  string
	DeviceSDK           services.DeviceManagerService
	DmsSDK              services.DMSManagerService
	AutomationProviders map[string]AutomationProviderInstance
	Logger              *logrus.Entry
}

func NewIotDeviceLifeCycleAutomationService(builder IotDeviceLifeCycleAutomationServiceBuilder) IotDeviceLifeCycleAutomationService {
	lIotAuto = builder.Logger

	return &IotDeviceLifeCycleAutomationImpl{
		lamassuInstanceURL:  builder.LamassuInstanceURL,
		deviceSDK:           builder.DeviceSDK,
		dmsSDK:              builder.DmsSDK,
		automationProviders: builder.AutomationProviders,
	}
}

func (svc *IotDeviceLifeCycleAutomationImpl) UpdateDigitalTwin(input UpdateDigitalTwinInput) error {
	device, err := svc.deviceSDK.GetDeviceByID(services.GetDeviceByIDInput{
		ID: input.DeviceID,
	})
	if err != nil {
		lIotAuto.Errorf("could not get device %s: %s", input.DeviceID, err)
		return err
	}

	dms, err := svc.dmsSDK.GetDMSByID(services.GetDMSByIDInput{
		ID: device.DMSOwnerID,
	})
	if err != nil {
		lIotAuto.Errorf("could not get DMS %s: %s", device.DMSOwnerID, err)
		return err
	}

	for connectorID, digitalTwinProvider := range svc.automationProviders {
		var dmsAutomationCfg any
		hasKey, err := helpers.GetMetadataToStruct(dms.Metadata, models.DeviceMetadataIotAutomationKey(connectorID), &dmsAutomationCfg)
		if err != nil {
			lIotAuto.Errorf("could not get connector %s metadata: %s", dms.ID, err)
			return nil
		}
		if !hasKey {
			lIotAuto.Warnf("connector %s is not configured for %s DMS", connectorID, dms.ID)
			return nil
		}

		lIotAuto.Infof("DMS %s is configured with IoT Automation", dms.ID)

		deviceMeta := device.Metadata
		var deviceAutomationMeta models.RemediateTracker
		hasKey, err = helpers.GetMetadataToStruct(deviceMeta, models.DeviceMetadataIotAutomationKey(connectorID), &deviceAutomationMeta)
		if err != nil {
			lIotAuto.Errorf("could not get device %s metadata: %s", device.ID, err)
			return nil
		}

		var prevDevDTwinState models.DigitalTwinIdentityState

		if !hasKey {
			lIotAuto.Infof("device %s has no automation metadata key for this connector. Will create Metadata Key %s", device.ID, models.DeviceMetadataIotAutomationKey(connectorID))
			deviceAutomationMeta = models.RemediateTracker{
				ActiveDigitalTwinIdentityState: models.DigitalTwinIdentityState{},
				Historical:                     []*models.DigitalTwinActionTracker{},
			}
		} else {
			lIotAuto.Infof("device %s has automation metadata key for this connector. Checking if remediation update is required", input.DeviceID)
		}

		prevDevDTwinState = deviceAutomationMeta.ActiveDigitalTwinIdentityState

		if _, hasKey := deviceAutomationMeta.ActiveDigitalTwinIdentityState[input.Action]; !hasKey {
			lIotAuto.Infof("device %s has no automation %s remediation action. Will create active remediation action", device.ID, input.Action)
			prevDevDTwinState[input.Action] = &models.DigitalTwinActionTracker{
				CreatedAt:  time.Now(),
				Remediated: true, //set to true, so Remediated == input.Remediated fails and forces Digital Twin Update
			}
		} else {
			lIotAuto.Infof("device %s already has %s remediation action", device.ID, input.Action)
		}

		if prevDevDTwinState[input.Action].Remediated == input.Remediated {
			lIotAuto.Debugf("requested remediation to be set to %t but device meta already reports in %t", input.Remediated, prevDevDTwinState[input.Action].Remediated)
			lIotAuto.Infof("device %s does not require an update on %s remediation action. Doing nothing", input.DeviceID, input.Action)
			return nil
		}

		lIotAuto.Infof("device %s require an update on %s remediation action", input.DeviceID, input.Action)
		lIotAuto.Debugf("requested remediation to be set to %t but device meta already reports in %t", input.Remediated, prevDevDTwinState[input.Action].Remediated)
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

		err = digitalTwinProvider.Provider.CreateDeviceDigitalTwinJob(CreateDeviceDigitalTwinJobInput{
			DeviceID:               input.DeviceID,
			Action:                 prevDevDTwinState[input.Action].State,
			DMSIoTAutomationConfig: dmsAutomationCfg,
		})
		if err != nil {
			lIotAuto.Errorf("error while updating digital twin for device %s with %s action: %s", device.ID, input.Action, err)
			return err
		}

		lIotAuto.Infof("updated digital twin for device %s with %s action", device.ID, input.Action)

		deviceMeta[models.DeviceMetadataIotAutomationKey(connectorID)] = deviceAutomationMeta

		_, err = svc.deviceSDK.UpdateDeviceMetadata(services.UpdateDeviceMetadataInput{
			ID:       input.DeviceID,
			Metadata: deviceMeta,
		})

		if err != nil {
			lIotAuto.Errorf("could not update device metadata: %s", err)
			return err
		}

		return nil
	}

	return nil
}
