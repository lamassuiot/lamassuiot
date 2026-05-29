package resources

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"

type UpdateEventRetentionSettingsBody struct {
	AuditEventTTL models.TimeDuration `json:"audit_event_ttl"`
}
