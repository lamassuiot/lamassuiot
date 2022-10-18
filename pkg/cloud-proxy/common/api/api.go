package api

import (
	"crypto/x509"
	"errors"
	"strings"
	"time"

	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
)

type ConsistencyStatus string

const (
	ConsistencyStatusDisabled     ConsistencyStatus = "DISABLED"
	ConsistencyStatusConsistent   ConsistencyStatus = "CONSISTENT"
	ConsistencyStatusInconsistent ConsistencyStatus = "INCONSISTENT"
)

type CloudConnector struct {
	CloudProvider   CloudProvider
	ID              string
	Name            string
	Status          string
	IP              string
	Protocol        string
	Port            int
	SynchronizedCAs []SynchronizedCA
	Configuration   interface{}
}

type CABinding struct {
	CAName           string
	SerialNumber     string
	EnabledTimestamp time.Time
}

type SynchronizedCA struct {
	CABinding
	ConsistencyStatus   ConsistencyStatus
	CloudProviderConfig interface{}
}

type CloudProvider string

const (
	CloudProviderAmazonWebServices CloudProvider = "AWS"
	CloudProviderMicrosoftAzure    CloudProvider = "AZURE"
)

func ParseCloudProviderType(s string) (CloudProvider, error) {
	s = strings.ToLower(s)
	switch s {
	case "aws":
		return CloudProviderAmazonWebServices, nil
	case "azure":
		return CloudProviderMicrosoftAzure, nil
	default:
		return "", errors.New("unsupported cloud provider type: " + s)
	}
}

type CloudProviderCAConfig struct {
	CAName string
	Config interface{}
}

type GetCloudConnectorsInput struct {
}

type GetCloudConnectorsOutput struct {
	CloudConnectors []CloudConnector
}

// ---------------------------------------------------

type GetCloudConnectorByIDInput struct {
	ConnectorID string
}

type GetCloudConnectorByIDOutput struct {
	CloudConnector
}

// ---------------------------------------------------

type GetDeviceConfigurationInput struct {
	ConnectorID string
	DeviceID    string
}

type GetDeviceConfigurationOutput struct {
	Configuration interface{}
}

// ---------------------------------------------------

type SynchronizeCAInput struct {
	CAName      string
	ConnectorID string
}

type SynchronizeCAOutput struct {
	CloudConnector
}

// ---------------------------------------------------

type UpdateCloudProviderConfigurationInput struct {
	ConnectorID string
	Config      interface{}
}

type UpdateCloudProviderConfigurationOutput struct {
	CloudConnector
}

// ---------------------------------------------------

type HandleCreateCAEventInput struct {
	caApi.CACertificate
}

type HandleCreateCAEventOutput struct {
}

// ---------------------------------------------------

type HandleUpdateCAStatusEventInput struct {
	caApi.CACertificate
}

type HandleUpdateCAStatusEventOutput struct {
}

// ---------------------------------------------------

type HandleUpdateCertificateStatusEventInput struct {
	caApi.Certificate
}

type HandleUpdateCertificateStatusEventOutput struct {
}

// ---------------------------------------------------

type UpdateDeviceCertificateStatusInput struct {
	ConnectorID  string
	DeviceID     string
	CAName       string
	SerialNumber string
	Status       string
}

type UpdateDeviceCertificateStatusOutput struct {
}

// ---------------------------------------------------

type UpdateCAStatusInput struct {
	ConnectorID string
	CAName      string
	Status      string
}

type UpdateCAStatusOutput struct {
}

// ---------------------------------------------------

type HandleReenrollEventInput struct {
	x509.Certificate
}

type HandleReenrollEventOutput struct {
}

// ---------------------------------------------------

type UpdateDeviceDigitalTwinReenrolmentStatusInput struct {
	ConnectorID   string
	DeviceID      string
	SlotID        string
	ForceReenroll bool
}

type UpdateDeviceDigitalTwinReenrolmentStatusOutput struct {
}

// ---------------------------------------------------

type HandleForceReenrollEventInput struct {
	DeviceID      string
	SlotID        string
	ForceReenroll bool
	Crt           *x509.Certificate
}

type HandleForceReenrollEventOutput struct {
}
