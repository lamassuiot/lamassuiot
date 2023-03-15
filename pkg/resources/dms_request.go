package resources

import "github.com/lamassuiot/lamassuiot/pkg/models"

type UpdateStatusBody struct {
	Status models.DMSStatus `json:"status"`
}

type CreateBody struct {
	CloudDMS                    bool                     `json:"cloud_dms"`
	Name                        string                   `json:"name"`
	Metadata                    map[string]string        `json:"metadata"`
	Tags                        []string                 `json:"tags"`
	RemoteAccessIdentityRequest *RemoteAccessIdentityReq `json:"remote_access_identity"`
}

type RemoteAccessIdentityReq struct {
	Subject               *models.Subject                `json:"subject"`
	ExternalKeyGeneration bool                           `json:"external_key"`
	CertificateRequest    *models.X509CertificateRequest `json:"csr"`
}
