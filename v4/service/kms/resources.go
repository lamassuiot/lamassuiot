package kms

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type CreateKeyBody struct {
	Algorithm string `json:"algorithm"`
	Size      int    `json:"size"`
	EngineID  string `json:"engine_id"`
	Name      string `json:"name"`
}

type SignMessageBody struct {
	Algorithm   string          `json:"algorithm"`
	Message     []byte          `json:"message"`
	MessageType SignMessageType `json:"message_type"`
}

type VerifySignBody struct {
	Algorithm   string          `json:"algorithm"`
	Message     []byte          `json:"message"`
	Signature   []byte          `json:"signature"`
	MessageType SignMessageType `json:"message_type"`
}

type ImportKeyBody struct {
	PrivateKey string `json:"private_key"`
	EngineID   string `json:"engine_id"`
	Name       string `json:"name"`
}

type GetKeysResponse struct {
	resources.IterableList[Key]
}
