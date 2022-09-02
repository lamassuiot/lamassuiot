package service

import (
	"context"
	"fmt"
	"net/url"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	consul "github.com/hashicorp/consul/api"
	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	cloudProviderClient "github.com/lamassuiot/lamassuiot/pkg/cloud-provider/client"
	cloudProvider "github.com/lamassuiot/lamassuiot/pkg/cloud-provider/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/common/api"
	cProxyErrors "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/repository"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

type Service interface {
	Health(ctx context.Context) bool
	GetCloudConnectors(ctx context.Context, input *api.GetCloudConnectorsInput) (*api.GetCloudConnectorsOutput, error)
	GetCloudConnectorByID(ctx context.Context, input *api.GetCloudConnectorByIDInput) (*api.GetCloudConnectorByIDOutput, error)
	GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (*api.GetDeviceConfigurationOutput, error)
	SynchronizeCA(ctx context.Context, input *api.SynchronizeCAInput) (*api.SynchronizeCAOutput, error)
	UpdateCloudProviderConfiguration(ctx context.Context, input *api.UpdateCloudProviderConfigurationInput) (*api.UpdateCloudProviderConfigurationOutput, error)
	HandleCreateCAEvent(ctx context.Context, input *api.HandleCreateCAEventInput) (*api.HandleCreateCAEventOutput, error)
	HandleUpdateCAStatusEvent(ctx context.Context, input *api.HandleUpdateCAStatusEventInput) (*api.HandleUpdateCAStatusEventOutput, error)
	HandleUpdateCertificateStatusEvent(ctx context.Context, input *api.HandleUpdateCertificateStatusEventInput) (*api.HandleUpdateCertificateStatusEventOutput, error)
	UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (*api.UpdateDeviceCertificateStatusOutput, error)
	UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error)
}

type CloudProxyService struct {
	Logger          log.Logger
	ConsulClient    *consul.Client
	LamassuCAClient lamassuCAClient.LamassuCAClient
	CloudProxyDB    repository.CloudProxyRepository
}

func NewCloudPorxyService(consulClient *consul.Client, cloudProxyDatabase repository.CloudProxyRepository, lamassuCAClient lamassuCAClient.LamassuCAClient, logger log.Logger) Service {
	return &CloudProxyService{
		Logger:          logger,
		ConsulClient:    consulClient,
		LamassuCAClient: lamassuCAClient,
		CloudProxyDB:    cloudProxyDatabase,
	}
}

func (s *CloudProxyService) Health(ctx context.Context) bool {
	return true
}

func (cps *CloudProxyService) GetCloudConnectors(ctx context.Context, input *api.GetCloudConnectorsInput) (*api.GetCloudConnectorsOutput, error) {
	cloudConnectors := make([]api.CloudConnector, 0)
	agents, err := cps.ConsulClient.Agent().ServicesWithFilter("Service == \"cloud-connector\"")
	if err != nil {
		return &api.GetCloudConnectorsOutput{}, err
	}

	for _, agent := range agents {
		connectorOut, err := cps.GetCloudConnectorByID(ctx, &api.GetCloudConnectorByIDInput{
			ConnectorID: agent.ID,
		})
		if err != nil {
			continue
		}

		cloudConnectors = append(cloudConnectors, connectorOut.CloudConnector)
	}

	return &api.GetCloudConnectorsOutput{
		CloudConnectors: cloudConnectors,
	}, nil
}

func (cps *CloudProxyService) GetCloudConnectorByID(ctx context.Context, input *api.GetCloudConnectorByIDInput) (*api.GetCloudConnectorByIDOutput, error) {
	agents, err := cps.ConsulClient.Agent().ServicesWithFilter(fmt.Sprintf("Service == \"cloud-connector\" and ID == \"%s\"", input.ConnectorID))
	if err != nil {
		return &api.GetCloudConnectorByIDOutput{}, err
	}

	if len(agents) != 1 {
		return &api.GetCloudConnectorByIDOutput{}, &cProxyErrors.ResourceNotFoundError{ResourceType: "CloudConnector", ResourceId: input.ConnectorID}
	}

	agent := agents[input.ConnectorID]
	status, _, err := cps.ConsulClient.Agent().AgentHealthServiceByID(agent.ID)
	if err != nil {
		return &api.GetCloudConnectorByIDOutput{}, err
	}

	connectorIp := agent.Address
	connectorPort := agent.Port
	connectorType, err := api.ParseCloudProviderType(agent.Meta["connector-type"])
	if err != nil {
		return &api.GetCloudConnectorByIDOutput{}, err
	}

	syncCAs := make([]api.SynchronizedCA, 0)
	caBindngs, err := cps.CloudProxyDB.SelectCABindingsByConnectorID(ctx, agent.ID)
	if err != nil {
		level.Debug(cps.Logger).Log("err", err)
		return &api.GetCloudConnectorByIDOutput{}, err
	}

	for _, caBindng := range caBindngs {
		syncCAs = append(syncCAs, api.SynchronizedCA{
			CABinding:           caBindng,
			ConsistencyStatus:   api.ConsistencyStatusDisabled, //Disabled by default. If Consul Agent is available, it will be either Inconsistent or Consistent.
			CloudProviderConfig: nil,
		})
	}

	if status != "passing" {
		return &api.GetCloudConnectorByIDOutput{
			CloudConnector: api.CloudConnector{
				ID:              agent.ID,
				Status:          status,
				Name:            agent.Meta["name"],
				CloudProvider:   connectorType,
				IP:              connectorIp,
				Port:            connectorPort,
				SynchronizedCAs: syncCAs,
				Protocol:        agent.Meta["protocol"],
				Configuration:   nil,
			},
		}, nil
	} else {
		connectorService, err := cps.newCloudPriverClient(agent.Meta["protocol"], connectorIp, connectorPort)
		if err != nil {
			level.Debug(cps.Logger).Log("err", err)
			return &api.GetCloudConnectorByIDOutput{}, err
		}

		getConfigOutput, err := connectorService.GetConfiguration(ctx, &cloudProvider.GetConfigurationInput{})
		if err != nil {
			level.Debug(cps.Logger).Log("msg", fmt.Sprintf("Could not get connector configuration [TYPE]=%s [ID]=%s [IP]=%s [PORT]=%d", connectorType, agent.ID, connectorIp, connectorPort), "err", err)
			return &api.GetCloudConnectorByIDOutput{}, err
		}

		for idx, syncCA := range syncCAs {
			if status == "passing" {
				syncCAs[idx].ConsistencyStatus = api.ConsistencyStatusInconsistent
				for _, cloudCA := range getConfigOutput.CAsConfiguration {
					if cloudCA.CAName == syncCA.CAName {
						syncCAs[idx].ConsistencyStatus = api.ConsistencyStatusConsistent
						syncCAs[idx].CloudProviderConfig = cloudCA.Configuration
					}
				}
			}
		}

		return &api.GetCloudConnectorByIDOutput{
			CloudConnector: api.CloudConnector{
				ID:              agent.ID,
				Status:          status,
				Name:            agent.Meta["name"],
				CloudProvider:   connectorType,
				IP:              connectorIp,
				Port:            connectorPort,
				Protocol:        agent.Meta["protocol"],
				SynchronizedCAs: syncCAs,
				Configuration:   getConfigOutput.Configuration,
			},
		}, nil
	}

}

func (cps *CloudProxyService) GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (*api.GetDeviceConfigurationOutput, error) {
	connector, err := cps.GetCloudConnectorByID(ctx, &api.GetCloudConnectorByIDInput{
		ConnectorID: input.ConnectorID,
	})
	if err != nil {
		return &api.GetDeviceConfigurationOutput{}, err
	}

	connectorClient, err := cps.newCloudPriverClientFromConnector(connector.CloudConnector)
	if err != nil {
		return &api.GetDeviceConfigurationOutput{}, err
	}

	deviceConfig, err := connectorClient.GetDeviceConfiguration(ctx, &cloudProvider.GetDeviceConfigurationInput{
		DeviceID: input.DeviceID,
	})

	if err != nil {
		return &api.GetDeviceConfigurationOutput{}, err
	}

	return &api.GetDeviceConfigurationOutput{
		Configuration: deviceConfig.Configuration,
	}, err
}

func (cps *CloudProxyService) SynchronizeCA(ctx context.Context, input *api.SynchronizeCAInput) (*api.SynchronizeCAOutput, error) {
	err := cps.CloudProxyDB.InsertCABinding(ctx, input.ConnectorID, input.CAName)
	if err != nil {
		return &api.SynchronizeCAOutput{}, err
	}

	connectorOutput, err := cps.GetCloudConnectorByID(ctx, &api.GetCloudConnectorByIDInput{
		ConnectorID: input.ConnectorID,
	})
	if err != nil {
		return &api.SynchronizeCAOutput{}, err
	}

	return &api.SynchronizeCAOutput{
		CloudConnector: connectorOutput.CloudConnector,
	}, nil
}

func (cps *CloudProxyService) UpdateCloudProviderConfiguration(ctx context.Context, input *api.UpdateCloudProviderConfigurationInput) (*api.UpdateCloudProviderConfigurationOutput, error) {
	connectorOutput, err := cps.GetCloudConnectorByID(ctx, &api.GetCloudConnectorByIDInput{
		ConnectorID: input.ConnectorID,
	})
	if err != nil {
		return &api.UpdateCloudProviderConfigurationOutput{}, err
	}

	connectorClient, err := cps.newCloudPriverClientFromConnector(connectorOutput.CloudConnector)
	if err != nil {
		return &api.UpdateCloudProviderConfigurationOutput{}, err
	}

	_, err = connectorClient.UpdateConfiguration(ctx, &cloudProvider.UpdateConfigurationInput{
		Configuration: input.Config,
	})

	return &api.UpdateCloudProviderConfigurationOutput{}, err
}

func (cps *CloudProxyService) HandleCreateCAEvent(ctx context.Context, input *api.HandleCreateCAEventInput) (*api.HandleCreateCAEventOutput, error) {
	connectorsOutput, err := cps.GetCloudConnectors(ctx, &api.GetCloudConnectorsInput{})
	if err != nil {
		return &api.HandleCreateCAEventOutput{}, err
	}

	for _, connector := range connectorsOutput.CloudConnectors {
		for _, syncCA := range connector.SynchronizedCAs {
			if syncCA.ConsistencyStatus != api.ConsistencyStatusDisabled && syncCA.CAName == input.CAName {
				fmt.Println(fmt.Sprintf("	[%s](%s) %s  --->  %s:%d", connector.Status, connector.CloudProvider, connector.ID, connector.IP, connector.Port))
				err := cps.CloudProxyDB.UpdateCABindingSerialNumber(ctx, connector.ID, input.CAName, input.SerialNumber)
				if err != nil {
					level.Debug(cps.Logger).Log("err", err)
					continue
				}

				connectorClient, err := cps.newCloudPriverClientFromConnector(connector)
				if err != nil {
					level.Debug(cps.Logger).Log("err", err)
					continue
				}

				_, err = connectorClient.RegisterCA(ctx, &cloudProvider.RegisterCAInput{
					CACertificate: input.CACertificate,
				})
				if err != nil {
					level.Debug(cps.Logger).Log("err", err)
					continue
				}
			}
		}
	}

	return &api.HandleCreateCAEventOutput{}, nil
}

func (cps *CloudProxyService) HandleUpdateCAStatusEvent(ctx context.Context, input *api.HandleUpdateCAStatusEventInput) (*api.HandleUpdateCAStatusEventOutput, error) {
	connectorsOutput, err := cps.GetCloudConnectors(ctx, &api.GetCloudConnectorsInput{})
	if err != nil {
		return &api.HandleUpdateCAStatusEventOutput{}, err
	}

	for _, connector := range connectorsOutput.CloudConnectors {
		for _, syncCA := range connector.SynchronizedCAs {
			if syncCA.ConsistencyStatus != api.ConsistencyStatusDisabled && syncCA.CAName == input.CAName {
				fmt.Println(fmt.Sprintf("	[%s](%s) %s  --->  %s:%d", connector.Status, connector.CloudProvider, connector.ID, connector.IP, connector.Port))
				err := cps.CloudProxyDB.UpdateCABindingSerialNumber(ctx, connector.ID, input.CAName, input.SerialNumber)
				if err != nil {
					level.Debug(cps.Logger).Log("err", err)
					continue
				}

				connectorClient, err := cps.newCloudPriverClientFromConnector(connector)
				if err != nil {
					level.Debug(cps.Logger).Log("err", err)
					continue
				}

				_, err = connectorClient.UpdateCAStatus(ctx, &cloudProvider.UpdateCAStatusInput{
					CAName: input.CAName,
					Status: string(input.Status),
				})
				if err != nil {
					level.Debug(cps.Logger).Log("err", err)
					continue
				}
			}
		}
	}
	return &api.HandleUpdateCAStatusEventOutput{}, nil
}

func (cps *CloudProxyService) HandleUpdateCertificateStatusEvent(ctx context.Context, input *api.HandleUpdateCertificateStatusEventInput) (*api.HandleUpdateCertificateStatusEventOutput, error) {
	connectorsOutput, err := cps.GetCloudConnectors(ctx, &api.GetCloudConnectorsInput{})
	if err != nil {
		return &api.HandleUpdateCertificateStatusEventOutput{}, err
	}

	for _, connector := range connectorsOutput.CloudConnectors {
		for _, syncCA := range connector.SynchronizedCAs {
			if syncCA.ConsistencyStatus != api.ConsistencyStatusDisabled && syncCA.CAName == input.CAName {
				fmt.Println(fmt.Sprintf("	[%s](%s) %s  --->  %s:%d", connector.Status, connector.CloudProvider, connector.ID, connector.IP, connector.Port))
				err := cps.CloudProxyDB.UpdateCABindingSerialNumber(ctx, connector.ID, input.CAName, input.SerialNumber)
				if err != nil {
					level.Debug(cps.Logger).Log("err", err)
					continue
				}

				cps.UpdateDeviceCertificateStatus(ctx, &api.UpdateDeviceCertificateStatusInput{
					ConnectorID:  connector.ID,
					DeviceID:     input.Certificate.Subject.CommonName,
					CAName:       input.CAName,
					Status:       string(input.Status),
					SerialNumber: input.SerialNumber,
				})

				if err != nil {
					level.Debug(cps.Logger).Log("err", err)
					continue
				}
			}
		}
	}
	return &api.HandleUpdateCertificateStatusEventOutput{}, nil
}

func (cps *CloudProxyService) UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (*api.UpdateDeviceCertificateStatusOutput, error) {
	connectorOutput, err := cps.GetCloudConnectorByID(ctx, &api.GetCloudConnectorByIDInput{
		ConnectorID: input.ConnectorID,
	})
	if err != nil {
		return &api.UpdateDeviceCertificateStatusOutput{}, err
	}

	connectorClient, err := cps.newCloudPriverClientFromConnector(connectorOutput.CloudConnector)
	if err != nil {
		return &api.UpdateDeviceCertificateStatusOutput{}, err
	}

	_, err = connectorClient.UpdateDeviceCertificateStatus(ctx, &cloudProvider.UpdateDeviceCertificateStatusInput{
		DeviceID:     input.DeviceID,
		Status:       input.Status,
		CAName:       input.CAName,
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return &api.UpdateDeviceCertificateStatusOutput{}, err
	}

	return &api.UpdateDeviceCertificateStatusOutput{}, nil
}

func (cps *CloudProxyService) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	return &api.UpdateCAStatusOutput{}, nil
}

func (cps *CloudProxyService) newCloudPriverClientFromConnector(connector api.CloudConnector) (cloudProviderClient.LamassuCloudProviderClient, error) {
	return cps.newCloudPriverClient(connector.Protocol, connector.IP, connector.Port)
}

func (cps *CloudProxyService) newCloudPriverClient(protocol string, ip string, port int) (cloudProviderClient.LamassuCloudProviderClient, error) {
	scheme := "http"
	if protocol == "https" {
		scheme = "https"
	}

	return cloudProviderClient.NewCloudProviderClient(clientUtils.BaseClientConfigurationuration{
		URL: &url.URL{
			Scheme: scheme,
			Host:   fmt.Sprintf("%s:%d", ip, port),
		},
		AuthMethod: clientUtils.AuthMethodNone,
		Insecure:   true,
	})
}
