package postgres

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository"
	"gorm.io/gorm"
)

type DeviceLogDAO struct {
	DeviceID       string `gorm:"primaryKey"`
	LogType        api.LogType
	LogMessage     string
	LogDescription string
	Timestamp      time.Time `gorm:"primaryKey"`
}

type SlotLogDAO struct {
	DeviceID       string    `gorm:"primaryKey"`
	SlotID         string    `gorm:"primaryKey"`
	Timestamp      time.Time `gorm:"primaryKey"`
	LogType        api.LogType
	LogMessage     string
	LogDescription string
}

func (SlotLogDAO) TableName() string {
	return "slot_logs"
}

func (DeviceLogDAO) TableName() string {
	return "device_logs"
}

func (d DeviceLogDAO) toLog() api.Log {
	return api.Log{
		LogType:        d.LogType,
		LogMessage:     d.LogMessage,
		LogDescription: d.LogDescription,
		Timestamp:      d.Timestamp,
	}
}

func (d SlotLogDAO) toLog() api.Log {
	return api.Log{
		LogType:        d.LogType,
		LogMessage:     d.LogMessage,
		LogDescription: d.LogDescription,
		Timestamp:      d.Timestamp,
	}
}

func NewLogsPostgresDB(db *gorm.DB, logger log.Logger) repository.DeviceLogs {
	db.AutoMigrate(&DeviceLogDAO{})
	db.AutoMigrate(&SlotLogDAO{})

	return &logsDBContext{db, logger}
}

type logsDBContext struct {
	*gorm.DB
	logger log.Logger
}

func (db *logsDBContext) InsertDeviceLog(ctx context.Context, deviceID string, logType api.LogType, logMessage string, logDescription string) error {
	log := DeviceLogDAO{
		DeviceID:       deviceID,
		LogType:        api.LogType(logType),
		LogMessage:     logMessage,
		LogDescription: logDescription,
		Timestamp:      time.Now(),
	}

	if err := db.Model(&DeviceLogDAO{}).Create(&log).Error; err != nil {
		return err
	}

	return nil
}

func (db *logsDBContext) SelectDeviceLogs(ctx context.Context, deviceID string) ([]api.Log, error) {
	var logs []DeviceLogDAO
	if err := db.Model(&DeviceLogDAO{}).Where("device_id = ?", deviceID).Find(&logs).Error; err != nil {
		return nil, err
	}

	result := []api.Log{}
	for _, log := range logs {
		parsedLog := log.toLog()
		result = append(result, parsedLog)
	}
	return result, nil
}

func (db *logsDBContext) InsertSlotLog(ctx context.Context, deviceID string, slotID string, logType api.LogType, logMessage string, logDescription string) error {
	log := SlotLogDAO{
		DeviceID:       deviceID,
		SlotID:         slotID,
		LogType:        api.LogType(logType),
		LogMessage:     logMessage,
		LogDescription: logDescription,
		Timestamp:      time.Now(),
	}

	if err := db.Model(&SlotLogDAO{}).Create(&log).Error; err != nil {
		return err
	}

	return nil
}

func (db *logsDBContext) SelectSlotLogs(ctx context.Context, deviceID string, slotID string) ([]api.Log, error) {
	var logs []SlotLogDAO
	if err := db.Model(&SlotLogDAO{}).Where("device_id = ?", deviceID).Find(&logs).Error; err != nil {
		return nil, err
	}

	result := []api.Log{}
	for _, log := range logs {
		parsedLog := log.toLog()
		result = append(result, parsedLog)
	}
	return result, nil
}
