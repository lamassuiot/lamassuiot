package resources

import (
	"github.com/lamassuiot/lamassuiot/pkg/models"
)

type UpdateDMSStatusBody struct {
	Status models.DMSStatus `json:"status"`
}

type CreateDMSBody struct {
	ID                   string                   `json:"id"`
	Name                 string                   `json:"name"`
	CloudDMS             bool                     `json:"cloud_dms"`
	Metadata             map[string]string        `json:"metadata"`
	Tags                 []string                 `json:"tags"`
	IdentityProfile      *IdentityProfileReq      `json:"identity_profile"`
	RemoteAccessIdentity *RemoteAccessIdentityReq `json:"remote_access_identity"`
}

type RemoteAccessIdentityReq struct {
	Subject               *models.Subject                `json:"subject"`
	ExternalKeyGeneration bool                           `json:"external_key"`
	CertificateRequest    *models.X509CertificateRequest `json:"csr"`
}

type IdentityProfileReq struct {
	EnrollmentSettings     EnrollmentSettingsReq         `json:"enrollment_settings"`
	ReEnrollmentSettings   models.ReEnrollmentSettings   `json:"reenrollment_settings"`
	CADistributionSettings models.CADistributionSettings `json:"ca_distribution_settings"`
}

type EnrollmentSettingsReq struct {
	EnrollmentProtocol      models.EnrollmentProto             `json:"protocol"`
	EnrollOptions           models.EnrollmentOptionsESTRFC7030 `json:"protocol_options"`
	DeviceProvisionSettings DeviceProvisionSettingsReq         `json:"device_provisioning"`
	AuthorizedCA            string                             `json:"authorized_ca"`
}

type DeviceProvisionSettingsReq struct {
	Icon      string            `json:"icon"`
	IconColor string            `json:"icon_color"`
	Metadata  map[string]string `json:"metadata"`
	Tags      []string          `json:"tags"`
}
