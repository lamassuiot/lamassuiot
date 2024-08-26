package handlers

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	smock "github.com/lamassuiot/lamassuiot/v2/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

func TestHandleUpdateMetadataUpdateShadow(t *testing.T) {

	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	//read event from testdata folder
	eventContent, err := os.ReadFile("testdata/update_metadata.json")
	if err != nil {
		t.Error(err)
	}

	message := message.Message{
		Payload: eventContent,
	}

	event, err := helpers.ParseCloudEvent(message.Payload)
	if err != nil {
		t.Error(err)
	}

	certUpdate, err := helpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		t.Error(err)
	}

	prevState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": false,
		},
	}

	newState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}

	certUpdate.Previous.Metadata["lamassu.io/ca/expiration-deltas"] = prevState
	certUpdate.Updated.Metadata["lamassu.io/ca/expiration-deltas"] = newState

	var eventMap map[string]interface{}
	json.Unmarshal(eventContent, &eventMap)
	eventMap["data"] = certUpdate

	content, err := json.Marshal(eventMap)
	if err != nil {
		t.Error(err)
	}
	message.Payload = content

	content, err = os.ReadFile("testdata/dms-settings.json")
	if err != nil {
		t.Error(err)
	}

	var dms models.DMS
	json.Unmarshal(content, &dms)

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	dmsMock := smock.MockDMSManagerService{}
	awsConnectorMock.On("GetDMSService").Return(&dmsMock)
	awsConnectorMock.On("GetConnectorID").Return("test")
	awsConnectorMock.On("UpdateDeviceShadow", mock.Anything, mock.Anything).Return(nil)
	dmsMock.On("GetDMSByID", mock.Anything, mock.Anything).Return(&dms, nil)

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(&message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertCalled(t, "UpdateDeviceShadow", mock.Anything, mock.Anything)
}

func TestHandleUpdateMetadataNotUpdateShadow(t *testing.T) {

	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	//read event from testdata folder
	eventContent, err := os.ReadFile("testdata/update_metadata.json")
	if err != nil {
		t.Error(err)
	}

	message := message.Message{
		Payload: eventContent,
	}

	event, err := helpers.ParseCloudEvent(message.Payload)
	if err != nil {
		t.Error(err)
	}

	certUpdate, err := helpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		t.Error(err)
	}

	prevState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}

	newState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}

	certUpdate.Previous.Metadata["lamassu.io/ca/expiration-deltas"] = prevState
	certUpdate.Updated.Metadata["lamassu.io/ca/expiration-deltas"] = newState

	var eventMap map[string]interface{}
	json.Unmarshal(eventContent, &eventMap)
	eventMap["data"] = certUpdate

	content, err := json.Marshal(eventMap)
	if err != nil {
		t.Error(err)
	}
	message.Payload = content

	content, err = os.ReadFile("testdata/dms-settings.json")
	if err != nil {
		t.Error(err)
	}

	var dms models.DMS
	json.Unmarshal(content, &dms)

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	dmsMock := smock.MockDMSManagerService{}
	awsConnectorMock.On("GetDMSService").Return(&dmsMock)
	awsConnectorMock.On("GetConnectorID").Return("test")
	dmsMock.On("GetDMSByID", mock.Anything, mock.Anything).Return(&dms, nil)

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(&message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNotCalled(t, "UpdateDeviceShadow", mock.Anything, mock.Anything)
}

func TestHandleUpdateMetadataDMSNoCondifuredNoUpdateShadow(t *testing.T) {

	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	//read event from testdata folder
	eventContent, err := os.ReadFile("testdata/update_metadata.json")
	if err != nil {
		t.Error(err)
	}

	message := message.Message{
		Payload: eventContent,
	}

	event, err := helpers.ParseCloudEvent(message.Payload)
	if err != nil {
		t.Error(err)
	}

	certUpdate, err := helpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		t.Error(err)
	}

	prevState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": false,
		},
	}

	newState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}

	certUpdate.Previous.Metadata["lamassu.io/ca/expiration-deltas"] = prevState
	certUpdate.Updated.Metadata["lamassu.io/ca/expiration-deltas"] = newState

	var eventMap map[string]interface{}
	json.Unmarshal(eventContent, &eventMap)
	eventMap["data"] = certUpdate

	content, err := json.Marshal(eventMap)
	if err != nil {
		t.Error(err)
	}
	message.Payload = content

	// Prepare DMS data
	content, err = os.ReadFile("testdata/dms-settings.json")
	if err != nil {
		t.Error(err)
	}

	var dms models.DMS
	json.Unmarshal(content, &dms)
	delete(dms.Metadata, "lamassu.io/iot/test")

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	dmsMock := smock.MockDMSManagerService{}
	awsConnectorMock.On("GetDMSService").Return(&dmsMock)
	awsConnectorMock.On("GetConnectorID").Return("test")
	dmsMock.On("GetDMSByID", mock.Anything, mock.Anything).Return(&dms, nil)

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(&message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNotCalled(t, "UpdateDeviceShadow", mock.Anything, mock.Anything)
}
