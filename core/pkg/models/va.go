package models

import (
	"time"
)

type VARole struct {
	CAID       string    `gorm:"column:caid;"`
	CRLOptions VACRLRole `gorm:"embedded;embeddedPrefix:crl_"`
}

type VACRLRole struct {
	RefreshInterval    TimeDuration `gorm:"serializer:text"`
	Validity           TimeDuration `gorm:"serializer:text"`
	LatestCRLVersion   BigInt       `gorm:"type:NUMERIC;serializer:text"`
	LastCRLTime        time.Time
	KeyIDSinger        string
	RegenerateOnRevoke bool
}
