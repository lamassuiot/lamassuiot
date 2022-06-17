package client

type AWSConfig struct {
	IotCoreEndpoint string         `json:"iot_core_endpoint"`
	AccountID       string         `json:"account_id"`
	CAs             []AWSIotCoreCA `json:"registered_cas"`
}
type AWSIotCoreCA struct {
	ARN            string `json:"arn"`
	CertificateID  string `json:"id"`
	CreationDate   string `json:"creation_date"`
	CAName         string `json:"name"`
	Status         string `json:"status"`
	PolicyStatus   string `json:"policy_status,omitempty"`
	PolicyDocumnet string `json:"policy_document,omitempty"`
}
type awsCreateIotCoreCA struct {
	CaName       string `json:"ca_name"`
	CaCert       string `json:"ca_cert"`
	SerialNumber string `json:"serial_number"`
}
type awsIotCoreCAAttachPolicy struct {
	Policy       string `json:"policy"`
	CaName       string `json:"ca_name"`
	SerialNumber string `json:"serial_number"`
}
type ThingsConfig struct {
	AwsID          string            `json:"aws_id"`
	Certificates   DeviceCertificate `json:"certificates"`
	DeviceID       string            `json:"device_id"`
	LastConnection string            `json:"last_connection"`
}
type DeviceCertificate struct {
	ARN        string `json:"arn"`
	Id         string `json:"id"`
	Status     string `json:"status"`
	UpdateDate string `json:"update_date"`
}
type awsUpdateCaStatus struct {
	CaName        string `json:"ca_name"`
	Status        string `json:"status"`
	CertificateID string `json:"certificate_id"`
}
type awsUpdateCertStatus struct {
	DeviceID     string `json:"device_id"`
	SerialNumber string `json:"serial_number"`
	Status       string `json:"status"`
	DeviceCert   string `json:"device_cert"`
	CaCert       string `json:"ca_cert"`
}
