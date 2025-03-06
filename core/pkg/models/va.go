package models

import (
	"time"
)

type VARole struct {
	CASubjectKeyID string        `gorm:"column:ca_ski;"`
	CRLOptions     VACRLRole     `gorm:"embedded;embeddedPrefix:crl_"`
	LatestCRL      LatestCRLMeta `gorm:"embedded;embeddedPrefix:latest_crl_"`
}

type VACRLRole struct {
	RefreshInterval    TimeDuration `gorm:"serializer:text"`
	Validity           TimeDuration `gorm:"serializer:text"`
	SubjectKeyIDSigner string
	RegenerateOnRevoke bool
}
type LatestCRLMeta struct {
	Version    BigInt `gorm:"type:NUMERIC;serializer:text"`
	ValidFrom  time.Time
	ValidUntil time.Time
}
