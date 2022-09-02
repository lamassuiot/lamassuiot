package api

import "time"

type CABindingSerialized struct {
	CAName           string `json:"ca_name"`
	SerialNumber     string `json:"serial_number"`
	EnabledTimestamp int    `json:"enabled_timestamp"`
}

func (o *CABinding) Serialize() CABindingSerialized {
	return CABindingSerialized{
		CAName:           o.CAName,
		SerialNumber:     o.SerialNumber,
		EnabledTimestamp: int(o.EnabledTimestamp.UnixMilli()),
	}
}

func (o *CABindingSerialized) Deserialize() CABinding {
	return CABinding{
		CAName:           o.CAName,
		SerialNumber:     o.SerialNumber,
		EnabledTimestamp: time.UnixMilli(int64(o.EnabledTimestamp)),
	}
}

type SynchronizedCASerialized struct {
	CABindingSerialized
	ConsistencyStatus   ConsistencyStatus `json:"consistency_status"`
	CloudProviderConfig interface{}       `json:"configuration"`
}

func (o *SynchronizedCA) Serialize() SynchronizedCASerialized {
	return SynchronizedCASerialized{
		CABindingSerialized: o.CABinding.Serialize(),
		ConsistencyStatus:   o.ConsistencyStatus,
		CloudProviderConfig: o.CloudProviderConfig,
	}
}

func (o *SynchronizedCASerialized) Deserialize() SynchronizedCA {
	return SynchronizedCA{
		CABinding:           o.CABindingSerialized.Deserialize(),
		ConsistencyStatus:   o.ConsistencyStatus,
		CloudProviderConfig: o.CloudProviderConfig,
	}
}

type CloudConnectorSerialized struct {
	CloudProvider   CloudProvider              `json:"cloud_provider"`
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	Status          string                     `json:"status"`
	IP              string                     `json:"ip"`
	Protocol        string                     `json:"protocol"`
	Port            int                        `json:"port"`
	SynchronizedCAs []SynchronizedCASerialized `json:"synchronized_cas"`
	Configuration   interface{}                `json:"configuration"`
}

func (o *CloudConnector) Serialize() CloudConnectorSerialized {
	syncCAs := make([]SynchronizedCASerialized, 0)
	for _, syncCA := range o.SynchronizedCAs {
		ca := syncCA.Serialize()
		syncCAs = append(syncCAs, ca)
	}
	return CloudConnectorSerialized{
		CloudProvider:   o.CloudProvider,
		ID:              o.ID,
		Name:            o.Name,
		Status:          o.Status,
		IP:              o.IP,
		Protocol:        o.Protocol,
		Port:            o.Port,
		Configuration:   o.Configuration,
		SynchronizedCAs: syncCAs,
	}
}

func (o *CloudConnectorSerialized) Deserialize() CloudConnector {
	syncCAs := make([]SynchronizedCA, 0)
	for _, syncCA := range o.SynchronizedCAs {
		ca := syncCA.Deserialize()
		syncCAs = append(syncCAs, ca)
	}
	return CloudConnector{
		CloudProvider:   o.CloudProvider,
		ID:              o.ID,
		Name:            o.Name,
		Status:          o.Status,
		IP:              o.IP,
		Protocol:        o.Protocol,
		Port:            o.Port,
		Configuration:   o.Configuration,
		SynchronizedCAs: syncCAs,
	}
}

//------------------------------------------------------

type GetCloudConnectorsSerialized struct {
	CloudConnectors []CloudConnectorSerialized `json:"cloud_connectors"`
}

func (o *GetCloudConnectorsOutput) Serialize() GetCloudConnectorsSerialized {
	cloudConnectors := make([]CloudConnectorSerialized, 0)
	for _, cloudConnector := range o.CloudConnectors {
		cloudConnector := cloudConnector.Serialize()
		cloudConnectors = append(cloudConnectors, cloudConnector)
	}

	return GetCloudConnectorsSerialized{
		CloudConnectors: cloudConnectors,
	}
}

func (o *GetCloudConnectorsSerialized) Deserialize() GetCloudConnectorsOutput {
	cloudConnectors := make([]CloudConnector, 0)
	for _, cloudConnector := range o.CloudConnectors {
		cloudConnector := cloudConnector.Deserialize()
		cloudConnectors = append(cloudConnectors, cloudConnector)
	}

	return GetCloudConnectorsOutput{
		CloudConnectors: cloudConnectors,
	}
}

//------------------------------------------------------
type GetCloudConnectorByIDOutputSerialized struct {
	CloudConnectorSerialized
}

func (o *GetCloudConnectorByIDOutput) Serialize() GetCloudConnectorByIDOutputSerialized {
	return GetCloudConnectorByIDOutputSerialized{
		CloudConnectorSerialized: o.CloudConnector.Serialize(),
	}
}

func (o *GetCloudConnectorByIDOutputSerialized) Deserialize() GetCloudConnectorByIDOutput {
	return GetCloudConnectorByIDOutput{
		CloudConnector: o.CloudConnectorSerialized.Deserialize(),
	}
}

//------------------------------------------------------

type GetDeviceConfigurationOutputSerialized interface{}

func (o *GetDeviceConfigurationOutput) Serialize() GetDeviceConfigurationOutputSerialized {
	return o.Configuration
}

//------------------------------------------------------

type SynchronizeCAOutputSerialized struct {
	CloudConnectorSerialized
}

func (o *SynchronizeCAOutput) Serialize() SynchronizeCAOutputSerialized {
	return SynchronizeCAOutputSerialized{
		CloudConnectorSerialized: o.CloudConnector.Serialize(),
	}
}

func (o *SynchronizeCAOutputSerialized) Deserialize() SynchronizeCAOutput {
	return SynchronizeCAOutput{
		CloudConnector: o.CloudConnectorSerialized.Deserialize(),
	}
}

//------------------------------------------------------

type UpdateCloudProviderConfigurationOutputSerialized struct {
	CloudConnectorSerialized
}

func (o *UpdateCloudProviderConfigurationOutput) Serialize() UpdateCloudProviderConfigurationOutputSerialized {
	return UpdateCloudProviderConfigurationOutputSerialized{
		CloudConnectorSerialized: o.CloudConnector.Serialize(),
	}
}

func (o *UpdateCloudProviderConfigurationOutputSerialized) Deserialize() UpdateCloudProviderConfigurationOutput {
	return UpdateCloudProviderConfigurationOutput{
		CloudConnector: o.CloudConnectorSerialized.Deserialize(),
	}
}

//------------------------------------------------------

type UpdateDeviceCertificateStatusOutputSerialized struct {
}

func (o *UpdateDeviceCertificateStatusOutput) Serialize() UpdateDeviceCertificateStatusOutputSerialized {
	return UpdateDeviceCertificateStatusOutputSerialized{}
}

func (o *UpdateDeviceCertificateStatusOutputSerialized) Deserialize() UpdateDeviceCertificateStatusOutput {
	return UpdateDeviceCertificateStatusOutput{}
}

//------------------------------------------------------

type UpdateCAStatusOutputSerialized struct {
}

func (o *UpdateCAStatusOutput) Serialize() UpdateCAStatusOutputSerialized {
	return UpdateCAStatusOutputSerialized{}
}

func (o *UpdateCAStatusOutputSerialized) Deserialize() UpdateCAStatusOutput {
	return UpdateCAStatusOutput{}
}
