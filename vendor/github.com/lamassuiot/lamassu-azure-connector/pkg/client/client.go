package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
)

type AzureConnectorClient interface {
	RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error
	// AttachAccessPolicy(ctx context.Context, caName string, caSerialNumber string, serializedAccessPolicy string) error
	// GetConfiguration(ctx context.Context) (AWSConfig, error)
	// GetDeviceConfiguration(ctx context.Context, deviceID string) (interface{}, error)
	// UpdateCaStatus(ctx context.Context, caName string, status string, certificateID string) error
	// UpdateCertStatus(ctx context.Context, caName string, serialNumber string, status string, deviceCert string, caCert string) error
}
type AzureConnectorClientConfig struct {
	client BaseClient
	logger log.Logger
	ID     string
}

func NewAzureConnectorClient(id string, ip string, port string, logger log.Logger) (AzureConnectorClient, error) {
	client := &http.Client{}
	url := ip + ":" + port

	return &AzureConnectorClientConfig{
		logger: logger,
		client: NewBaseClient(url, client),
		ID:     id,
	}, nil
}

func (s *AzureConnectorClientConfig) RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error {
	level.Info(s.logger).Log("msg", "Resgitering CA to Azure")

	azureCreateDpsCA := azureCreateDpsCA{
		CaName:       caName,
		Certificate:  caCertificate,
		SerialNumber: caSerialNumber,
	}
	azureCreateDpsCABytes, err := json.Marshal(azureCreateDpsCA)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	req, err := s.client.NewRequest("POST", "/v1/create-ca", azureCreateDpsCABytes)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}
	_, err = s.client.Do(req)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	return nil
}

func (s *AzureConnectorClientConfig) UpdateCaStatus(ctx context.Context, caName string, status string, certificateID string) error {
	level.Info(s.logger).Log("msg", "Update CA Status to AWS")

	awsUpdateCaStatus := awsUpdateCaStatus{
		CaName:        caName,
		Status:        status,
		CertificateID: certificateID,
	}
	awsUpdateCaStatusBytes, err := json.Marshal(awsUpdateCaStatus)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	req, err := s.client.NewRequest("PUT", "/v1/ca/status", awsUpdateCaStatusBytes)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}
	_, err = s.client.Do(req)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	return nil
}
func (s *AzureConnectorClientConfig) UpdateCertStatus(ctx context.Context, deviceID string, serialNumber string, status string, deviceCert string, caCert string) error {
	level.Info(s.logger).Log("msg", "Update Cert Status to AWS")

	awsUpdateCertStatus := awsUpdateCertStatus{
		DeviceID:     deviceID,
		SerialNumber: serialNumber,
		Status:       status,
		DeviceCert:   deviceCert,
		CaCert:       caCert,
	}
	awsUpdateCertStatusBytes, err := json.Marshal(awsUpdateCertStatus)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	req, err := s.client.NewRequest("PUT", "/v1/cert/status", awsUpdateCertStatusBytes)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}
	_, err = s.client.Do(req)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	return nil
}
func (s *AzureConnectorClientConfig) AttachAccessPolicy(ctx context.Context, caName string, caSerialNumber string, serializedAccessPolicy string) error {
	fmt.Println("Calling attach access policy", s.ID, caName, serializedAccessPolicy)

	awsIotCoreCAAttachPolicy := awsIotCoreCAAttachPolicy{
		Policy:       serializedAccessPolicy,
		CaName:       caName,
		SerialNumber: caSerialNumber,
	}
	fmt.Println(awsIotCoreCAAttachPolicy)

	awsCreateIotCoreCABytes, err := json.Marshal(awsIotCoreCAAttachPolicy)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	req, err := s.client.NewRequest("POST", "/v1/attach-policy", awsCreateIotCoreCABytes)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}
	_, err = s.client.Do(req)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	return nil
}

func (s *AzureConnectorClientConfig) GetConfiguration(ctx context.Context) (AWSConfig, error) {
	var config AWSConfig
	req, err := s.client.NewRequest("GET", "/v1/config", nil)

	if err != nil {
		level.Error(s.logger).Log("err", err)
		return AWSConfig{}, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return AWSConfig{}, err
	}
	err = json.NewDecoder(resp.Body).Decode(&config)
	return config, nil
}

func (s *AzureConnectorClientConfig) GetDeviceConfiguration(ctx context.Context, deviceID string) (interface{}, error) {
	var v interface{}
	req, err := s.client.NewRequest("GET", "/v1/things/"+deviceID+"/config", nil)

	if err != nil {
		level.Error(s.logger).Log("err", err)
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&v)
	if err != nil {
		return nil, err
	}
	return v, nil
}
