package dms

import "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"

type DmsCreationForm struct {
	Name        string                 `json:"name"`
	Subject     dto.Subject            `json:"subject"`
	KeyMetadata dto.PrivateKeyMetadata `json:"key_metadata"`
	Url         string                 `json:"url"`
}
type AuthorizedCAs struct {
	DmsId  string
	CaName string
}

const (
	PendingStatus  = "PENDING_APPROVAL"
	ApprovedStatus = "APPROVED"
	DeniedStatus   = "DENIED"
	RevokedStatus  = "REVOKED"
)
