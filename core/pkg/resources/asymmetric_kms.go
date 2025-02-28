package resources

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"

type SignatureSignBody struct {
	Message          string                 `json:"message"`
	MessageType      models.SignMessageType `json:"message_type"`
	SigningAlgorithm string                 `json:"signature_algorithm"`
}

type SignatureVerifyBody struct {
	Signature        string                 `json:"signature"`
	Message          string                 `json:"message"`
	MessageType      models.SignMessageType `json:"message_type"`
	SigningAlgorithm string                 `json:"signature_algorithm"`
}
