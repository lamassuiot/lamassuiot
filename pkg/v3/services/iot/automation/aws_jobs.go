package iotautomation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

type AWSIoTAutomation struct {
	iotSDK       iot.Client
	AwsAccountID string
	Region       string
}

type AWSIotAutomationBuilder struct {
	Conf   aws.Config
	Logger *logrus.Entry
}

func NewAWSIotAutomationService(builder AWSIotAutomationBuilder) (IotDeviceAutomationJobServiceProvider, error) {
	iotLogger := builder.Logger.WithField("sdk", "AWS IoT Client")
	stsLogger := builder.Logger.WithField("sdk", "AWS STS Client")

	// derefIotHttpCli := &builder.BaseHttpClient
	iotHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, iotLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	stsHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, stsLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	iotConf := builder.Conf
	iotConf.HTTPClient = iotHttpCli
	iotClient := iot.NewFromConfig(iotConf)

	stsConf := builder.Conf
	stsConf.HTTPClient = stsHttpCli
	stsClient := sts.NewFromConfig(iotConf)

	callIDOutput, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	return &AWSIoTAutomation{
		iotSDK:       *iotClient,
		AwsAccountID: *callIDOutput.Account,
		Region:       builder.Conf.Region,
	}, nil
}

func (svc *AWSIoTAutomation) CreateDeviceDigitalTwinJob(input CreateDeviceDigitalTwinJobInput) error {
	var dmsAwsAutomationConfig models.DMSMetadataIotPlatformAWS
	b, err := json.Marshal(input.DMSIoTAutomationConfig)
	if err != nil {
		return fmt.Errorf("could not decode DMS automation config: %s", err)
	}

	err = json.Unmarshal(b, &dmsAwsAutomationConfig)
	if err != nil {
		return fmt.Errorf("invalid DMS automation config for AWS IoT Automation")
	}

	if dmsAwsAutomationConfig.JobsEnabled {
		logrus.Warnf("Jobs are not enabled for DMS associated to device %s", input.DeviceID)
	}

	event := messaging.BuildCloudEvent("lamassu.io/device/iot-automation/command", "a", input.Action)
	jobBytes, err := event.MarshalJSON()
	if err != nil {
		return fmt.Errorf("error while serializing Command Job message: %s", err)
	}

	_, err = svc.iotSDK.CreateJob(context.Background(), &iot.CreateJobInput{
		JobId: aws.String(fmt.Sprintf("lms-%s-%s", input.Action.RemediationType, uuid.NewString())),
		Targets: []string{
			*aws.String(fmt.Sprintf("arn:aws:iot:%s:%s:thing/%s", svc.Region, svc.AwsAccountID, input.DeviceID)),
		},
		Description: aws.String("LAMASSU Remediation Action"),
		Document:    aws.String(string(jobBytes)),
	})
	if err != nil {
		logrus.Errorf("could not create AWS Job for thing %s: %s", input.DeviceID, err)
		return err
	}

	logrus.Infof("created AWS Job for thing %s", input.DeviceID)

	return nil
}
