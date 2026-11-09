package auditpub

import (
	coreaudit "github.com/lamassuiot/lamassuiot/v4/core/pkg/audit"
	coreeventpub "github.com/lamassuiot/lamassuiot/v4/core/pkg/eventpub"
)

type AuditBody = coreaudit.AuditBody
type AuditPublisher = coreaudit.AuditPublisher

func NewAuditPublisher(publisher coreeventpub.ICloudEventPublisher) *AuditPublisher {
	return coreaudit.NewAuditPublisher(publisher)
}
