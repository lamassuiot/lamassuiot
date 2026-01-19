package models

import "time"

type CryptoSecretType string

const (
	TokenSlotProfile      CryptoSecretType = "TOKEN"
	X509SlotProfileType   CryptoSecretType = "x509"
	SshKeySlotProfileType CryptoSecretType = "SSH_KEY"
	OtherSlotProfileType  CryptoSecretType = "OTHER"
)

type Slot[E any] struct {
	Status         string           `json:"status"`
	ActiveVersion  int              `json:"active_version"`
	SecretType     CryptoSecretType `json:"type"`
	Secrets        map[int]E        `json:"versions"` // version -> secret
	ExpirationDate *time.Time       `json:"expiration_date,omitempty"`
}

type SlotX509Status string

const (
	SlotX509StatusNotSet        SlotX509Status = "NOT_SET"
	SlotX509StatusActive        SlotX509Status = "ACTIVE"
	SlotX509StatusRenewalWindow SlotX509Status = "RENEWAL_PENDING" //PreventiveEnroll
	SlotX509StatusAboutToExpire SlotX509Status = "EXPIRING_SOON"
	SlotX509StatusExpired       SlotX509Status = "EXPIRED"
	SlotX509StatusRevoked       SlotX509Status = "REVOKED"
)
