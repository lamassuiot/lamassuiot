package handlers

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	smock "github.com/lamassuiot/lamassuiot/v2/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

func TestHandleUpdateMetadata(t *testing.T) {

	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	//read event from testdata folder
	content, err := os.ReadFile("testdata/update_metadata.json")
	if err != nil {
		t.Error(err)
	}

	message := message.Message{
		Payload: content,
	}

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
