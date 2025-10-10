package kms

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"

const (
	EventCreateKMSKey          models.EventType = "kms.create"
	EventImportKMSKey          models.EventType = "kms.import"
	EventDeleteKMSKey          models.EventType = "kms.delete"
	EventSignMessageKMSKey     models.EventType = "kms.sign"
	EventVerifySignatureKMSKey models.EventType = "kms.verify"
)
