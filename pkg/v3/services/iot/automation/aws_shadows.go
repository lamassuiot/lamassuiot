package iot

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iotdataplane"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

type AWSShadowsAutomation struct {
	deviceSDK       services.DeviceManagerService
	dmsSDK          services.DMSManagerService
	iotdataplaneSDK iotdataplane.Client
}

func NewAWSIotDeviceLifeCycleAutomationService() (IotDeviceLifeCycleAutomationService, error) {
	return &AWSShadowsAutomation{}, nil
}

func (svc *AWSShadowsAutomation) UpdateDigitalTwin(input UpdateDigitalTwinInput) error {
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
		logrus.Errorf("could not get device %s: %s", input.DeviceID, err)
		return err
	}

	fmt.Println("dms", dms)
	return nil
}

func (svc *AWSShadowsAutomation) GetRemediateTrackers() ([]*RemediateTracker, error) {
	return nil, nil
}
