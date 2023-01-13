package api

type CABindingLogSerialized struct {
	CAName       string `json:"ca_name"`
	SerialNumber string `json:"serial_number"`
}

func (o *CABinding) ToSerializedLog() CABindingLogSerialized {
	return CABindingLogSerialized{
		CAName:       o.CAName,
		SerialNumber: o.SerialNumber,
	}
}

type SynchronizedCALogSerialized struct {
	CABindingLogSerialized
	ConsistencyStatus ConsistencyStatus `json:"consistency_status"`
}

func (o *SynchronizedCA) ToSerializedLog() SynchronizedCALogSerialized {
	return SynchronizedCALogSerialized{
		CABindingLogSerialized: o.CABinding.ToSerializedLog(),
		ConsistencyStatus:      o.ConsistencyStatus,
	}
}

type CloudConnectorLogSerialized struct {
	CloudProvider   CloudProvider                 `json:"cloud_provider"`
	ID              string                        `json:"id"`
	Name            string                        `json:"name"`
	Status          string                        `json:"status"`
	SynchronizedCAs []SynchronizedCALogSerialized `json:"synchronized_cas"`
}

func (o *CloudConnector) ToSerializedLog() CloudConnectorLogSerialized {
	syncCAs := make([]SynchronizedCALogSerialized, 0)
	for _, syncCA := range o.SynchronizedCAs {
		ca := syncCA.ToSerializedLog()
		syncCAs = append(syncCAs, ca)
	}
	return CloudConnectorLogSerialized{
		CloudProvider:   o.CloudProvider,
		ID:              o.ID,
		Name:            o.Name,
		Status:          o.Status,
		SynchronizedCAs: syncCAs,
	}
}

//------------------------------------------------------

type GetCloudConnectorsLogSerialized struct {
	CloudConnectors []CloudConnectorLogSerialized `json:"cloud_connectors"`
}

func (o *GetCloudConnectorsOutput) ToSerializedLog() GetCloudConnectorsLogSerialized {
	cloudConnectors := make([]CloudConnectorLogSerialized, 0)
	for _, cloudConnector := range o.CloudConnectors {
		cloudConnector := cloudConnector.ToSerializedLog()
		cloudConnectors = append(cloudConnectors, cloudConnector)
	}

	return GetCloudConnectorsLogSerialized{
		CloudConnectors: cloudConnectors,
	}
}

// ------------------------------------------------------
type GetCloudConnectorByIDOutputLogSerialized struct {
	CloudConnectorLogSerialized
}

func (o *GetCloudConnectorByIDOutput) ToSerializedLog() GetCloudConnectorByIDOutputLogSerialized {
	return GetCloudConnectorByIDOutputLogSerialized{
		CloudConnectorLogSerialized: o.CloudConnector.ToSerializedLog(),
	}
}

//------------------------------------------------------

type GetDeviceConfigurationOutputLogSerialized interface{}

func (o *GetDeviceConfigurationOutput) ToSerializedLog() GetDeviceConfigurationOutputLogSerialized {
	return o.Configuration
}

//------------------------------------------------------

type SynchronizeCAOutputLogSerialized struct {
	CloudConnectorLogSerialized
}

func (o *SynchronizeCAOutput) ToSerializedLog() SynchronizeCAOutputLogSerialized {
	return SynchronizeCAOutputLogSerialized{
		CloudConnectorLogSerialized: o.CloudConnector.ToSerializedLog(),
	}
}

//------------------------------------------------------

type UpdateCloudProviderConfigurationOutputLogSerialized struct {
	CloudConnectorLogSerialized
}

func (o *UpdateCloudProviderConfigurationOutput) ToSerializedLog() UpdateCloudProviderConfigurationOutputLogSerialized {
	return UpdateCloudProviderConfigurationOutputLogSerialized{
		CloudConnectorLogSerialized: o.CloudConnector.ToSerializedLog(),
	}
}

//------------------------------------------------------

type UpdateDeviceCertificateStatusOutputLogSerialized struct {
}

func (o *UpdateDeviceCertificateStatusOutput) ToSerializedLog() UpdateDeviceCertificateStatusOutputLogSerialized {
	return UpdateDeviceCertificateStatusOutputLogSerialized{}
}

//------------------------------------------------------

type UpdateCAStatusOutputLogSerialized struct {
}

func (o *UpdateCAStatusOutput) ToSerializedLog() UpdateCAStatusOutputLogSerialized {
	return UpdateCAStatusOutputLogSerialized{}
}

//------------------------------------------------------

type UpdateDeviceDigitalTwinReenrolmentStatusOutputLogSerialized struct {
}

func (o *UpdateDeviceDigitalTwinReenrolmentStatusOutput) ToSerializedLog() UpdateDeviceDigitalTwinReenrolmentStatusOutputLogSerialized {
	return UpdateDeviceDigitalTwinReenrolmentStatusOutputLogSerialized{}
}
