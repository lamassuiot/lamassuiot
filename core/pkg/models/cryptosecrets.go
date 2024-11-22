package models

type CryptoSecretType string

const (
	TokenSlotProfile      CryptoSecretType = "TOKEN"
	X509SlotProfileType   CryptoSecretType = "x509"
	SshKeySlotProfileType CryptoSecretType = "SSH_KEY"
	OtherSlotProfileType  CryptoSecretType = "OTHER"
)
