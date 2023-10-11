package iotplatform

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"golang.org/x/net/context"
)

type IotPlatformService interface {
	GetCloudConfiguration(context.Context) (any, error)
	GetRegisteredCAs(context.Context) ([]*models.CACertificate, error)
	RegisterCA(context.Context, RegisterCAInput) (*models.CACertificate, error)
}

type RegisterCAInput struct {
	models.CACertificate
	RegisterConfiguration any
}
