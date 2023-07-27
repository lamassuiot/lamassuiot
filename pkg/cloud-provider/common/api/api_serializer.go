package api

type CAConfigurationSerialized struct {
	CAName        string      `json:"ca_name"`
	Configuration interface{} `json:"configuration"`
}

func (o *CAConfiguration) Serialize() CAConfigurationSerialized {
	return CAConfigurationSerialized{
		CAName:        o.CAName,
		Configuration: o.Configuration,
	}
}

func (o *CAConfigurationSerialized) Deserialize() CAConfiguration {
	return CAConfiguration{
		CAName:        o.CAName,
		Configuration: o.Configuration,
	}
}

//------------------------------------------------------

type RegisterCAOutputSerialized struct {
}

func (o *RegisterCAOutput) Serialize() RegisterCAOutputSerialized {
	return RegisterCAOutputSerialized{}
}

func (o *RegisterCAOutputSerialized) Deserialize() RegisterCAOutput {
	return RegisterCAOutput{}
}

//------------------------------------------------------

type UpdateConfigurationOutputSerialized struct {
	Configuration interface{} `json:"configuration"`
}

func (o *UpdateConfigurationOutput) Serialize() UpdateConfigurationOutputSerialized {
	return UpdateConfigurationOutputSerialized{
		Configuration: o.Configuration,
	}
}

func (o *UpdateConfigurationOutputSerialized) Deserialize() UpdateConfigurationOutput {
	return UpdateConfigurationOutput{
		Configuration: o.Configuration,
	}
}

//------------------------------------------------------

type GetConfigurationOutputSerialized struct {
	Configuration    interface{}                 `json:"configuration"`
	CAsConfiguration []CAConfigurationSerialized `json:"cas"`
}

func (o *GetConfigurationOutput) Serialize() GetConfigurationOutputSerialized {
	casConfig := []CAConfigurationSerialized{}
	for _, ca := range o.CAsConfiguration {
		casConfig = append(casConfig, ca.Serialize())
	}
	return GetConfigurationOutputSerialized{
		Configuration:    o.Configuration,
		CAsConfiguration: casConfig,
	}
}

func (o *GetConfigurationOutputSerialized) Deserialize() GetConfigurationOutput {
	casConfig := []CAConfiguration{}
	for _, ca := range o.CAsConfiguration {
		casConfig = append(casConfig, ca.Deserialize())
	}
	return GetConfigurationOutput{
		Configuration:    o.Configuration,
		CAsConfiguration: casConfig,
	}
}

//------------------------------------------------------

type GetDeviceConfigurationOutputSerialized interface{}

func (o *GetDeviceConfigurationOutput) Serialize() GetDeviceConfigurationOutputSerialized {
	return o.Configuration
}

// ------------------------------------------------------
type UpdateCAStatusOutputSerialized struct {
}

func (o *UpdateCAStatusOutput) Serialize() UpdateCAStatusOutputSerialized {
	return UpdateCAStatusOutputSerialized{}
}

func (o *UpdateCAStatusOutputSerialized) Deserialize() UpdateCAStatusOutput {
	return UpdateCAStatusOutput{}
}

// ------------------------------------------------------
type UpdateDeviceCertificateStatusOutputSerialized struct {
}

func (o *UpdateDeviceCertificateStatusOutput) Serialize() UpdateDeviceCertificateStatusOutputSerialized {
	return UpdateDeviceCertificateStatusOutputSerialized{}
}

func (o *UpdateDeviceCertificateStatusOutputSerialized) Deserialize() UpdateDeviceCertificateStatusOutput {
	return UpdateDeviceCertificateStatusOutput{}
}

// ------------------------------------------------------
type UpdateDeviceDigitalTwinReenrollmentStatusOutputSerialized struct{}

func (o *UpdateDeviceDigitalTwinReenrollmentStatusOutput) Serialize() UpdateDeviceDigitalTwinReenrollmentStatusOutputSerialized {
	return UpdateDeviceDigitalTwinReenrollmentStatusOutputSerialized{}
}

//------------------------------------------------------

type UpdateDMSCaCertsOutputSerialized struct {
}

func (o *UpdateDMSCaCertsOutput) Serialize() UpdateDMSCaCertsOutputSerialized {
	return UpdateDMSCaCertsOutputSerialized{}
}

func (o *UpdateDMSCaCertsOutputSerialized) Deserialize() UpdateDMSCaCertsOutput {
	return UpdateDMSCaCertsOutput{}
}
