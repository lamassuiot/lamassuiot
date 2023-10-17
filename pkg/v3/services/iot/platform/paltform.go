package iotplatform

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/net/context"
)

type IotPlatformService interface {
	// GetCloudConfiguration(context.Context) (any, error)
	GetRegisteredCAs(context.Context) ([]*models.CACertificate, error)
	RegisterCA(context.Context, RegisterCAInput) (*models.CACertificate, error)
	RegisterUpdateJITPProvisioner(context.Context, RegisterJITPProvisionerInput) (map[string]any, error)
}

type RegisterCAInput struct {
	models.CACertificate
	RegisterConfiguration any
}

type RegisterJITPProvisionerInput struct {
	DMS *models.DMS
}

type IotPlatformImpl struct {
	platformProviders map[string]IotPlatformService
}

type IotPlatformBuilder struct {
	PlatformProviders map[string]IotPlatformService
}

func NewIotPlatform(builder IotPlatformBuilder) IotPlatformService {
	return &IotPlatformImpl{
		platformProviders: builder.PlatformProviders,
	}
}

func (svc *IotPlatformImpl) GetRegisteredCAs(context.Context) ([]*models.CACertificate, error) {
	return nil, nil
}

func (svc *IotPlatformImpl) RegisterCA(ctx context.Context, input RegisterCAInput) (*models.CACertificate, error) {
	for connectorID, platformProvider := range svc.platformProviders {
		var registerCA bool
		hasKey, err := helpers.GetMetadataToStruct(input.Metadata, models.CAMetadataIotAutomationKey(connectorID), &registerCA)
		if err != nil {
			logrus.Errorf("error while getting %s key: %s", models.CAMetadataIotAutomationKey(connectorID), err)
			return nil, err
		}

		if !hasKey {
			return &input.CACertificate, nil
		}

		if !registerCA {
			// TODO if register CA is false, check if it was already registered. If so, remove registration
		}

		//check if CA already registered in AWS
		cas, err := svc.GetRegisteredCAs(context.Background())
		if err != nil {
			logrus.Errorf("could not get Registered CAs: %s", err)
			return nil, err
		}

		alreadyRegistered := false
		idx := slices.IndexFunc[*models.CACertificate](cas, func(c *models.CACertificate) bool {
			if c.SerialNumber == input.SerialNumber {
				return true
			} else {
				return false
			}
		})

		if idx != -1 {
			alreadyRegistered = true
		}

		if !alreadyRegistered {
			logrus.Infof("registering CA with SN '%s'", input.SerialNumber)
			ca, err := platformProvider.RegisterCA(context.Background(), RegisterCAInput{CACertificate: input.CACertificate})
			if err != nil {
				logrus.Errorf("something went wrong while registering CA with SN '%s' in %s connector. Skipping event handling: %s", ca.SerialNumber, connectorID, err)
				return nil, err
			}
		} else {
			logrus.Warnf("CA with SN '%s' is already registered in AWS IoT. Skipping registration process", input.SerialNumber)
		}
	}

	return &input.CACertificate, nil
}

func (svc *IotPlatformImpl) RegisterUpdateJITPProvisioner(context.Context, RegisterJITPProvisionerInput) (map[string]any, error) {
	return nil, nil
}
