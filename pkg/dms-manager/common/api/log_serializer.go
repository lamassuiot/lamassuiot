package api

type SubjectLogSerialized struct {
	CommonName string `json:"common_name"`
}

func (o *Subject) ToSerializedLog() SubjectLogSerialized {
	serializer := SubjectLogSerialized{
		CommonName: o.CommonName,
	}
	return serializer
}

type DeviceManufacturingServiceLogSerialized struct {
	Name          string               `json:"name"`
	Status        DMSStatus            `json:"status"`
	SerialNumber  string               `json:"serial_number"`
	Subject       SubjectLogSerialized `json:"subject"`
	AuthorizedCAs []string             `json:"authorized_cas"`
}

func (o *DeviceManufacturingService) ToSerializedLog() DeviceManufacturingServiceLogSerialized {
	serializer := DeviceManufacturingServiceLogSerialized{
		Name:          o.Name,
		Status:        o.Status,
		SerialNumber:  o.SerialNumber,
		Subject:       o.Subject.ToSerializedLog(),
		AuthorizedCAs: o.AuthorizedCAs,
	}

	return serializer
}

// -------------------------------------------------------------

type GetDMSByNameOutputLogSerialized struct {
	DeviceManufacturingServiceLogSerialized
}

func (o *GetDMSByNameOutput) ToSerializedLog() GetDMSByNameOutputLogSerialized {
	serializer := GetDMSByNameOutputLogSerialized{
		DeviceManufacturingServiceLogSerialized: o.DeviceManufacturingService.ToSerializedLog(),
	}
	return serializer
}

// ----------------------------------------------

type GetDMSsOutputLogSerialized struct {
	TotalDMSs int `json:"total_dmss"`
}

func (o *GetDMSsOutput) ToSerializedLog() GetDMSsOutputLogSerialized {
	serializer := GetDMSsOutputLogSerialized{
		TotalDMSs: o.TotalDMSs,
	}
	return serializer
}

// ----------------------------------------------

type CreateDMSWithCertificateRequestOutputlOGSerialized struct {
	DeviceManufacturingServiceLogSerialized
}

func (o *CreateDMSWithCertificateRequestOutput) ToSerializedLog() CreateDMSWithCertificateRequestOutputlOGSerialized {
	serializer := CreateDMSWithCertificateRequestOutputlOGSerialized{
		DeviceManufacturingServiceLogSerialized: o.DeviceManufacturingService.ToSerializedLog(),
	}
	return serializer
}

// ----------------------------------------------

type CreateDMSOutputLogSerialized struct {
	DMS DeviceManufacturingServiceSerialized `json:"dms"`
}

func (o *CreateDMSOutput) ToSerializedLog() CreateDMSOutputLogSerialized {
	serializer := CreateDMSOutputLogSerialized{
		DMS: o.DMS.Serialize(),
	}
	return serializer
}

// ----------------------------------------------

type UpdateDMSStatusOutputLogSerialized struct {
	DeviceManufacturingServiceLogSerialized
}

func (o *UpdateDMSStatusOutput) ToSerializedLog() UpdateDMSStatusOutputLogSerialized {
	serializer := UpdateDMSStatusOutputLogSerialized{
		DeviceManufacturingServiceLogSerialized: o.DeviceManufacturingService.ToSerializedLog(),
	}
	return serializer
}

// ----------------------------------------------

type UpdateDMSAuthorizedCAsOutputLogSerialized struct {
	DeviceManufacturingServiceLogSerialized
}

func (o *UpdateDMSAuthorizedCAsOutput) ToSerializedLog() UpdateDMSAuthorizedCAsOutputLogSerialized {
	serializer := UpdateDMSAuthorizedCAsOutputLogSerialized{
		DeviceManufacturingServiceLogSerialized: o.DeviceManufacturingService.ToSerializedLog(),
	}
	return serializer
}
