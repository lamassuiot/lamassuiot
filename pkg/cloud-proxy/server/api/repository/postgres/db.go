package db

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/common/api"
	cProxyErrors "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/repository"
	"gorm.io/gorm"

	_ "github.com/lib/pq"
)

type CABindingDAO struct {
	ConnectorID       string `gorm:"primaryKey"`
	CAName            string `gorm:"primaryKey"`
	SerialNumber      string
	CreationTimestamp time.Time
}

func (CABindingDAO) TableName() string {
	return "ca_bindings"
}

func (c *CABindingDAO) toCABinding() api.CABinding {
	return api.CABinding{
		CAName:           c.CAName,
		SerialNumber:     c.SerialNumber,
		EnabledTimestamp: c.CreationTimestamp,
	}
}

type PostgresDBContext struct {
	*gorm.DB
}

func NewPostgresDB(db *gorm.DB) repository.CloudProxyRepository {
	db.AutoMigrate(&CABindingDAO{})

	return &PostgresDBContext{db}
}

func (db *PostgresDBContext) InsertCABinding(ctx context.Context, connectorID string, caName string) error {
	tx := db.Model(&CABindingDAO{}).Create(&CABindingDAO{
		ConnectorID:       connectorID,
		CAName:            caName,
		SerialNumber:      "",
		CreationTimestamp: time.Now(),
	})

	if tx.Error != nil {
		duplicationErr := &cProxyErrors.DuplicateResourceError{
			ResourceType: "CA Binding",
			ResourceId:   "ConnectorID: " + connectorID + " CA Name: " + caName,
		}
		return duplicationErr
	}

	return nil
}

func (db *PostgresDBContext) UpdateCABindingSerialNumber(ctx context.Context, connectorID string, caName string, caSerialNumber string) error {
	var caBinding CABindingDAO
	if err := db.Model(&CABindingDAO{}).Where("connector_id = ?", connectorID).Where("ca_name = ?", caName).First(&caBinding).Error; err != nil {
		return err
	}

	caBinding.SerialNumber = caSerialNumber

	if err := db.Save(&caBinding).Error; err != nil {
		return err
	}

	return nil
}

func (db *PostgresDBContext) SelectCABindingsByConnectorID(ctx context.Context, connectorID string) ([]api.CABinding, error) {
	var caBindings []CABindingDAO
	if err := db.Model(&CABindingDAO{}).Where("connector_id = ?", connectorID).Find(&caBindings).Error; err != nil {
		return []api.CABinding{}, err
	}

	var cas []api.CABinding
	for _, v := range caBindings {
		cas = append(cas, v.toCABinding())
	}

	return cas, nil
}

func (db *PostgresDBContext) SelectCABindingByConnectorIDAndCAName(ctx context.Context, connectorID string, caName string) (api.CABinding, error) {
	var caBinding CABindingDAO
	if err := db.Model(&CABindingDAO{}).Where("connector_id = ?", connectorID).Where("ca_name = ?", caName).First(&caBinding).Error; err != nil {
		return api.CABinding{}, err
	}

	return caBinding.toCABinding(), nil
}
