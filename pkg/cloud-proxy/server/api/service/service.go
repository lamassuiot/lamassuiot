package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	consul "github.com/hashicorp/consul/api"
	"github.com/lamassuiot/lamassu-aws-connector/pkg/client"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	lamassuErrors "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/errors"
	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"
	cloudProviderClient "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers/instances"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers/store"
)

type Service interface {
	Health(ctx context.Context) bool
	GetCloudConnectors(ctx context.Context) ([]cloudproviders.CloudConnector, error)
	GetCloudConnectorByID(ctx context.Context, cloudConnectorID string) (cloudproviders.CloudConnector, error)
	GetDeviceConfiguration(ctx context.Context, cloudConnectorID string, deviceID string) (interface{}, error)
	SynchronizeCA(ctx context.Context, cloudConnectorID string, caName string, enabledTs time.Time) (cloudproviders.CloudConnector, error)
	UpdateSecurityAccessPolicy(ctx context.Context, cloudConnectorID string, caName string, serializedSecurityAccessPolicy string) (cloudproviders.CloudConnector, error)

	HandleCreateCAEvent(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error
	HandleUpdateCaStatusEvent(ctx context.Context, caName string, status string) error
	HandleUpdateCertStatusEvent(ctx context.Context, caName string, serialNumber string, status string) error
	UpdateCertStatus(ctx context.Context, deviceID string, certSerialNumber string, status string, connectorID string, caName string) error
	UpdateCaStatus(ctx context.Context, caName string, status string) error
}

type cloudProxyService struct {
	logger             log.Logger
	consulClient       *consul.Client
	LamassuCaClient    lamassucaclient.LamassuCaClient
	cloudProxyDatabase store.DB
}

func NewCloudPorxyService(consulClient *consul.Client, cloudProxyDatabase store.DB, lamassuCAClient lamassucaclient.LamassuCaClient, logger log.Logger) Service {
	return &cloudProxyService{
		logger:             logger,
		consulClient:       consulClient,
		LamassuCaClient:    lamassuCAClient,
		cloudProxyDatabase: cloudProxyDatabase,
	}
}
func (s *cloudProxyService) Health(ctx context.Context) bool {
	return true
}

func (s *cloudProxyService) GetCloudConnectors(ctx context.Context) ([]cloudproviders.CloudConnector, error) {
	cloudConnectors := make([]cloudproviders.CloudConnector, 0)

	agents, err := s.consulClient.Agent().ServicesWithFilter("Service == \"cloud-connector\"")
	if err != nil {
		return cloudConnectors, err
	}

	for _, agent := range agents {
		status, _, err := s.consulClient.Agent().AgentHealthServiceByID(agent.ID)
		if err != nil {
			continue
		}

		connectorTypeString := agent.Meta["connector-type"]
		connectorIp := agent.Address
		connectorPort := strconv.Itoa(agent.Port)

		connectortType, err := cloudproviders.ParseCloudProviderType(connectorTypeString)
		if err != nil {
			level.Error(s.logger).Log("err", err)
			continue
		}

		syncCAs := make([]cloudproviders.SynchronizedCA, 0)
		databaseSyncCAs, err := s.cloudProxyDatabase.SelectSynchronizedCAsByConnectorID(ctx, agent.ID)
		if err != nil {
			continue
		}

		for _, dbSyncCA := range databaseSyncCAs {
			syncCAs = append(syncCAs, cloudproviders.SynchronizedCA{
				CAName:           dbSyncCA.CAName,
				SerialNumber:     dbSyncCA.SerialNumber,
				EnabledTimestamp: dbSyncCA.EnabledTimestamp,
			})
		}

		if status != "passing" {
			cloudConnectors = append(cloudConnectors, cloudproviders.CloudConnector{
				ID:              agent.ID,
				Status:          status,
				Name:            agent.Meta["name"],
				CloudProvider:   connectorTypeString,
				IP:              connectorIp,
				Port:            connectorPort,
				SynchronizedCAs: syncCAs,
				Configuration:   nil,
			})
		} else {
			connectorService, err := cloudProviderClient.NewCloudConnectorService(agent.ID, connectorIp, connectorPort, connectortType, s.logger)
			if err != nil {
				level.Error(s.logger).Log("err", err)
				continue
			}

			generalConfig, casConfig, err := connectorService.GetConfiguration(ctx)
			if err != nil {
				level.Error(s.logger).Log("msg", "Could not get connector configuration [TYPE]= "+connectorTypeString+" [ID]="+agent.ID+" [IP]="+connectorIp+" [PORT]="+connectorPort, "err", err)
				continue
			}

			for idx, syncCA := range syncCAs {
				syncCAs[idx].ConsistencyStatus = cloudproviders.ConsistencyStatus_Disabled.String()
				if status == "passing" {
					syncCAs[idx].ConsistencyStatus = cloudproviders.ConsistencyStatus_Inconsistent.String()
					for _, cloudCA := range casConfig {
						if cloudCA.CAName == syncCA.CAName {
							syncCAs[idx].ConsistencyStatus = cloudproviders.ConsistencyStatus_Consistent.String()
							syncCAs[idx].CloudProviderConfig = cloudCA.Config
						}
					}
				}
			}

			cloudConnectors = append(cloudConnectors, cloudproviders.CloudConnector{
				ID:              agent.ID,
				Status:          status,
				Name:            agent.Meta["name"],
				CloudProvider:   connectorTypeString,
				IP:              connectorIp,
				Port:            connectorPort,
				SynchronizedCAs: syncCAs,
				Configuration:   generalConfig,
			})
		}
	}

	return cloudConnectors, nil
}

func (s *cloudProxyService) GetCloudConnectorByID(ctx context.Context, cloudConnectorID string) (cloudproviders.CloudConnector, error) {
	connectors, err := s.GetCloudConnectors(ctx)
	if err != nil {
		return cloudproviders.CloudConnector{}, err
	}
	for _, connector := range connectors {
		if connector.ID == cloudConnectorID {
			return connector, nil
		}
	}
	return cloudproviders.CloudConnector{}, &lamassuErrors.ResourceNotFoundError{ResourceType: "CloudConnector", ResourceId: cloudConnectorID}
}

func (s *cloudProxyService) GetDeviceConfiguration(ctx context.Context, cloudConnectorID string, deviceID string) (interface{}, error) {
	connector, err := s.GetCloudConnectorByID(ctx, cloudConnectorID)
	if err != nil {
		return []client.ThingsConfig{}, err
	}
	connectorClient, err := cloudProviderClient.NewCloudConnectorServiceFromCloudConnector(connector, s.logger)
	if err != nil {
		return []client.ThingsConfig{}, err
	}

	devicesConfig, err := connectorClient.GetDeviceConfiguration(ctx, deviceID)
	return devicesConfig, err
}

func (s *cloudProxyService) SynchronizeCA(ctx context.Context, cloudConnectorID string, caName string, enabledTs time.Time) (cloudproviders.CloudConnector, error) {
	err := s.cloudProxyDatabase.InsertSynchronizedCA(ctx, cloudConnectorID, caName, enabledTs)
	if err != nil {
		return cloudproviders.CloudConnector{}, err
	} else {
		cloudConnectors, err := s.GetCloudConnectors(ctx)
		if err != nil {
			return cloudproviders.CloudConnector{}, err
		}

		for _, cloudConnector := range cloudConnectors {
			if cloudConnector.ID == cloudConnectorID {
				return cloudConnector, nil
			}
		}
		return cloudproviders.CloudConnector{}, nil
	}
}

func (s *cloudProxyService) UpdateSecurityAccessPolicy(ctx context.Context, cloudConnectorID string, caName string, serializedSecurityAccessPolicy string) (cloudproviders.CloudConnector, error) {
	cloudConnectors, err := s.GetCloudConnectors(ctx)
	if err != nil {
		return cloudproviders.CloudConnector{}, err
	}

	var cloudConnector cloudproviders.CloudConnector
	for _, connector := range cloudConnectors {
		if connector.ID == cloudConnectorID {
			cloudConnector = connector
		}
	}

	if cloudConnector.ID == "" {
		return cloudproviders.CloudConnector{}, errors.New("connector not found")
	}

	var syncCA cloudproviders.SynchronizedCA
	for _, currentSyncCA := range cloudConnector.SynchronizedCAs {
		if currentSyncCA.CAName == caName {
			syncCA = currentSyncCA
		}
	}

	if syncCA.CAName == "" {
		return cloudproviders.CloudConnector{}, errors.New("no matching CA. Maybe out of sync")
	}
	connectortType, err := cloudproviders.ParseCloudProviderType(cloudConnector.CloudProvider)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return cloudproviders.CloudConnector{}, err
	}
	connectorService, err := cloudProviderClient.NewCloudConnectorService(cloudConnector.ID, cloudConnector.IP, cloudConnector.Port, connectortType, s.logger)
	if err != nil {
		return cloudproviders.CloudConnector{}, err
	}

	err = connectorService.AttachAccessPolicy(ctx, caName, syncCA.SerialNumber, serializedSecurityAccessPolicy)
	if err != nil {

	}

	return cloudConnector, nil
}

func (s *cloudProxyService) HandleCreateCAEvent(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error {
	syncCAs, err := s.cloudProxyDatabase.SelectSynchronizedCAsByCaName(ctx, caName)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get synchronized CA list")
		return err
	}

	activeCloudConnectors, err := s.GetCloudConnectors(ctx)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get active cloud connector list")
		return err
	}

	for _, syncCA := range syncCAs {
		for _, activeCloudConnector := range activeCloudConnectors {
			if activeCloudConnector.ID == syncCA.CloudConnectorID {
				level.Info(s.logger).Log("msg", "Found existing synchronization between CloudConnector"+activeCloudConnector.ID+" and caName "+caName)
				fmt.Println("	[" + activeCloudConnector.Status + "] " + activeCloudConnector.ID + "   " + activeCloudConnector.IP + ":" + activeCloudConnector.Port + "/" + activeCloudConnector.CloudProvider)

				s.cloudProxyDatabase.UpdateSynchronizedCA(ctx, activeCloudConnector.ID, caName, caSerialNumber)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectortType, err := cloudproviders.ParseCloudProviderType(activeCloudConnector.CloudProvider)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectorService, err := cloudProviderClient.NewCloudConnectorService(activeCloudConnector.ID, activeCloudConnector.IP, activeCloudConnector.Port, connectortType, s.logger)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectorService.RegisterCA(ctx, caName, caSerialNumber, caCertificate)
			}
		}
	}
	return nil
}

func (s *cloudProxyService) HandleUpdateCaStatusEvent(ctx context.Context, caName string, status string) error {
	syncCAs, err := s.cloudProxyDatabase.SelectSynchronizedCAsByCaName(ctx, caName)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get synchronized CA list")
		return err
	}

	activeCloudConnectors, err := s.GetCloudConnectors(ctx)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get active cloud connector list")
		return err
	}

	for _, syncCA := range syncCAs {
		for _, activeCloudConnector := range activeCloudConnectors {
			if activeCloudConnector.ID == syncCA.CloudConnectorID {
				level.Info(s.logger).Log("msg", "Found existing synchronization between CloudConnector"+activeCloudConnector.ID+" and caName "+caName)
				fmt.Println("	[" + activeCloudConnector.Status + "] " + activeCloudConnector.ID + "   " + activeCloudConnector.IP + ":" + activeCloudConnector.Port + "/" + activeCloudConnector.CloudProvider)

				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectortType, err := cloudproviders.ParseCloudProviderType(activeCloudConnector.CloudProvider)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectorService, err := cloudProviderClient.NewCloudConnectorService(activeCloudConnector.ID, activeCloudConnector.IP, activeCloudConnector.Port, connectortType, s.logger)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}
				_, casConfig, err := connectorService.GetConfiguration(ctx)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					return err
				}
				var certificateID string
				for _, ca := range casConfig {
					if ca.CAName == caName {
						caConfig := ca.Config.(client.AWSIotCoreCA)
						certificateID = caConfig.CertificateID
						break
					}
				}
				connectorService.UpdateCaStatus(ctx, caName, status, certificateID)
			}
		}
	}
	return nil
}

func (s *cloudProxyService) HandleUpdateCertStatusEvent(ctx context.Context, caName string, certSerialNumber string, status string) error {
	syncCAs, err := s.cloudProxyDatabase.SelectSynchronizedCAsByCaName(ctx, caName)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get synchronized CA list")
		return err
	}
	ctx = context.WithValue(ctx, "LamassuLogger", s.logger)
	deviceCert, err := s.LamassuCaClient.GetCert(ctx, dto.Pki, caName, certSerialNumber)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get the device certificate")
		return err
	}

	deviceID := deviceCert.Subject.CommonName
	activeCloudConnectors, err := s.GetCloudConnectors(ctx)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get active cloud connector list")
		return err
	}

	for _, syncCA := range syncCAs {
		for _, activeCloudConnector := range activeCloudConnectors {
			if activeCloudConnector.ID == syncCA.CloudConnectorID {
				caCert, err := s.LamassuCaClient.GetCert(ctx, dto.Pki, caName, syncCA.SerialNumber)
				if err != nil {
					level.Error(s.logger).Log("err", err, "msg", "could not get the device certificate")
					return err
				}
				level.Info(s.logger).Log("msg", "Found existing synchronization between CloudConnector"+activeCloudConnector.ID+" and caName "+caName)
				fmt.Println("	[" + activeCloudConnector.Status + "] " + activeCloudConnector.ID + "   " + activeCloudConnector.IP + ":" + activeCloudConnector.Port + "/" + activeCloudConnector.CloudProvider)

				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectortType, err := cloudproviders.ParseCloudProviderType(activeCloudConnector.CloudProvider)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectorService, err := cloudProviderClient.NewCloudConnectorService(activeCloudConnector.ID, activeCloudConnector.IP, activeCloudConnector.Port, connectortType, s.logger)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}
				connectorService.UpdateCertStatus(ctx, deviceID, certSerialNumber, status, deviceCert.CertContent.CerificateBase64, caCert.CertContent.CerificateBase64)
			}
		}
	}
	return nil
}

func (s *cloudProxyService) UpdateCertStatus(ctx context.Context, deviceID string, certSerialNumber string, status string, connectorID string, caName string) error {
	activeCloudConnectors, err := s.GetCloudConnectors(ctx)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get active cloud connector list")
		return err
	}
	deviceCert, err := s.LamassuCaClient.GetCert(ctx, dto.Pki, caName, certSerialNumber)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get the device certificate")
		return err
	}
	syncCAs, err := s.cloudProxyDatabase.SelectSynchronizedCAsByCaName(ctx, caName)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get synchronized CA list")
		return err
	}
	for _, syncCA := range syncCAs {
		for _, activeCloudConnector := range activeCloudConnectors {
			if activeCloudConnector.ID == connectorID {
				caCert, err := s.LamassuCaClient.GetCert(ctx, dto.Pki, caName, syncCA.SerialNumber)
				if err != nil {
					level.Error(s.logger).Log("err", err, "msg", "could not get the device certificate")
					return err
				}
				level.Info(s.logger).Log("msg", "Found existing synchronization between CloudConnector"+activeCloudConnector.ID)
				fmt.Println("	[" + activeCloudConnector.Status + "] " + activeCloudConnector.ID + "   " + activeCloudConnector.IP + ":" + activeCloudConnector.Port + "/" + activeCloudConnector.CloudProvider)

				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectortType, err := cloudproviders.ParseCloudProviderType(activeCloudConnector.CloudProvider)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectorService, err := cloudProviderClient.NewCloudConnectorService(activeCloudConnector.ID, activeCloudConnector.IP, activeCloudConnector.Port, connectortType, s.logger)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}
				connectorService.UpdateCertStatus(ctx, deviceID, certSerialNumber, status, deviceCert.CertContent.CerificateBase64, caCert.CertContent.CerificateBase64)
			}
		}
	}
	return nil
}

func (s *cloudProxyService) UpdateCaStatus(ctx context.Context, caName string, status string) error {
	syncCAs, err := s.cloudProxyDatabase.SelectSynchronizedCAsByCaName(ctx, caName)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get synchronized CA list")
		return err
	}

	activeCloudConnectors, err := s.GetCloudConnectors(ctx)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "could not get active cloud connector list")
		return err
	}

	for _, syncCA := range syncCAs {
		for _, activeCloudConnector := range activeCloudConnectors {
			if activeCloudConnector.ID == syncCA.CloudConnectorID {
				level.Info(s.logger).Log("msg", "Found existing synchronization between CloudConnector"+activeCloudConnector.ID+" and caName "+caName)
				fmt.Println("	[" + activeCloudConnector.Status + "] " + activeCloudConnector.ID + "   " + activeCloudConnector.IP + ":" + activeCloudConnector.Port + "/" + activeCloudConnector.CloudProvider)

				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectortType, err := cloudproviders.ParseCloudProviderType(activeCloudConnector.CloudProvider)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}

				connectorService, err := cloudProviderClient.NewCloudConnectorService(activeCloudConnector.ID, activeCloudConnector.IP, activeCloudConnector.Port, connectortType, s.logger)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					continue
				}
				_, casConfig, err := connectorService.GetConfiguration(ctx)
				if err != nil {
					level.Error(s.logger).Log("err", err)
					return err
				}
				var certificateID string
				for _, ca := range casConfig {
					if ca.CAName == caName {
						caConfig := ca.Config.(client.AWSIotCoreCA)
						certificateID = caConfig.CertificateID
						break
					}
				}
				connectorService.UpdateCaStatus(ctx, caName, status, certificateID)
			}
		}
	}
	return nil
}
