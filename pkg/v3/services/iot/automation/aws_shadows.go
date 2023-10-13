package iot

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iotdataplane"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

type AWSShadowsAutomation struct {
	iotdataplaneSDK iotdataplane.Client
}

func NewAWSIotDeviceLifeCycleAutomationService() (IotDeviceLifeCycleAutomationServiceProvider[models.DMSMetadataIotAutomationAWS], error) {
	return &AWSShadowsAutomation{}, nil
}

func (svc *AWSShadowsAutomation) UpdateDeviceDigitalTwin(input UpdateDeviceDigitalTwinInput[models.DMSMetadataIotAutomationAWS]) error {
	awsUpdateShadow := &iotdataplane.UpdateThingShadowInput{
		ThingName: &input.DeviceID,
		Payload:   input.BodyMessage,
	}

	if input.DMSIoTAutomationConfig.ShadowType == models.AWSIoTShadowNamed {
		awsUpdateShadow.ShadowName = &input.DMSIoTAutomationConfig.NamedShadowName
	}

	_, err := svc.iotdataplaneSDK.UpdateThingShadow(context.Background(), awsUpdateShadow)
	if err != nil {
		logrus.Errorf("could not update AWS shadow for thing %s: %s", input.DeviceID, err)
		return err
	}

	logrus.Infof("updated AWS shadow for thing %s", input.DeviceID)

	return nil
}

func (svc *AWSShadowsAutomation) GetRemediateTrackers() ([]*models.RemediateTracker, error) {
	return nil, nil
}
