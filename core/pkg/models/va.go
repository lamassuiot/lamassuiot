package models

import (
	"time"
)

type VARole struct {
	CAID       string        `gorm:"column:caid;"`
	CRLOptions VACRLRole     `gorm:"embedded;embeddedPrefix:crl_"`
	LatestCRL  LatestCRLMeta `gorm:"embedded;embeddedPrefix:latest_crl_"`
}

type VACRLRole struct {
	RefreshInterval    TimeDuration `gorm:"serializer:text"`
	Validity           TimeDuration `gorm:"serializer:text"`
	KeyIDSigner        string
	RegenerateOnRevoke bool
}
type LatestCRLMeta struct {
	Version    BigInt `gorm:"type:NUMERIC;serializer:text"`
	ValidFrom  time.Time
	ValidUntil time.Time
}
