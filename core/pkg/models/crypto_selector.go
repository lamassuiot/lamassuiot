package models

import "time"

// DedicatedCryptoSelector identifies the CA, engine and key serving a tenant.
type DedicatedCryptoSelector struct {
	TenantID  string    `json:"tenant_id" gorm:"primaryKey"`
	CAID      string    `json:"ca_id"`
	EngineID  string    `json:"engine_id"`
	KeyID     string    `json:"key_id"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}
