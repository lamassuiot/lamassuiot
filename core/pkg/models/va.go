package models

import (
	"math/big"
	"time"
)

type VARole struct {
	CAID       string    `gorm:"column:caid;"`
	CRLOptions VACRLRole `gorm:"embedded;embeddedPrefix:crl_"`
}

type VACRLRole struct {
	RefreshInterval    TimeDuration
	Validity           TimeDuration
	LatestCRLVersion   *big.Int `gorm:"type:NUMERIC"`
	LastCRLTime        time.Time
	KeyIDSinger        string
	RegenerateOnRevoke bool
}
