package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	common "github.com/lamassuiot/lamassu-azure-connector/pkg/common"
)

type AzureConnectorClient interface {

	// Azure-connector functionalities
	CreateCa(ctx context.Context, caName string, SerialNumber string, Certificate string) error
	RevokeCa(ctx context.Context, caName string) error
	RevokeCertificate(ctx context.Context, deviceId string) error
	UpdateCaCertificate(ctx context.Context, caName string) error
	UpdateCertificate(ctx context.Context, deviceId string, newStatus string) error
	GetDeviceConfiguration(ctx context.Context, deviceId string) common.DeviceInfo
	GetAzureConfiguration(ctx context.Context) (common.AzureConfig, error)
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

func (s *AzureConnectorClientConfig) CreateCa(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error {
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

func (s *AzureConnectorClientConfig) RevokeCa(ctx context.Context, caName string) error {
	level.Info(s.logger).Log("msg", "Revoking CA certificate from Azure.")

	revokeCaBody := RevokeCaBody{
		CaName: caName,
	}

	azureRevokeCaBytes, err := json.Marshal(revokeCaBody)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	req, err := s.client.NewRequest("POST", "/v1/revoke-ca", azureRevokeCaBytes)
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

func (s *AzureConnectorClientConfig) RevokeCertificate(ctx context.Context, deviceId string) error {

	level.Info(s.logger).Log("msg", "Revoking certificate from Azure.")
	revokeCertificateBody := RevokeCertificateBody{
		DeviceId: deviceId,
	}

	azureRevokeCertificateBytes, err := json.Marshal(revokeCertificateBody)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	req, err := s.client.NewRequest("POST", "/v1/revoke-cert", azureRevokeCertificateBytes)
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

func (s *AzureConnectorClientConfig) UpdateCaCertificate(ctx context.Context, caName string) error {

	level.Info(s.logger).Log("msg", "Updating Ca certificate from Azure.")
	updateCaCertificateBody := UpdateCaCertificateBody{
		CaName: caName,
	}

	updateCaCertificateBytes, err := json.Marshal(updateCaCertificateBody)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	req, err := s.client.NewRequest("PUT", "/v1/update-ca", updateCaCertificateBytes)
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

func (s *AzureConnectorClientConfig) UpdateCertificate(ctx context.Context, deviceId string, newStatus string) error {

	level.Info(s.logger).Log("msg", "Updating Ca certificate from Azure.")
	updateCertificateBody := UpdateCertificateBody{
		DeviceId: deviceId,
	}

	updateCertificateBytes, err := json.Marshal(updateCertificateBody)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return err
	}

	req, err := s.client.NewRequest("PUT", "/v1/update-cert", updateCertificateBytes)
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

func (s *AzureConnectorClientConfig) GetDeviceConfiguration(ctx context.Context, deviceId string) common.DeviceInfo {
	level.Info(s.logger).Log("msg", "Getting device configuration from Azure.")
	getDeviceConfigurationBody := GetDeviceConfigurationBody{
		DeviceId: deviceId,
	}

	getDeviceConfigurationBytes, err := json.Marshal(getDeviceConfigurationBody)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return common.DeviceInfo{}
	}

	req, err := s.client.NewRequest("GET", "/v1/device", getDeviceConfigurationBytes)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return common.DeviceInfo{}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return common.DeviceInfo{}
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		level.Error(s.logger).Log("req", err)
	}
	var deviceInfor common.DeviceInfo

	err = json.Unmarshal(bodyBytes, &deviceInfor)
	if err != nil {
		level.Error(s.logger).Log("err", err)
	}
	return deviceInfor
}

func (s *AzureConnectorClientConfig) GetAzureConfiguration(ctx context.Context) (common.AzureConfig, error) {
	level.Info(s.logger).Log("msg", "Getting device configuration from Azure.")

	req, err := s.client.NewRequest("GET", "/v1/azure-config", nil)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return common.AzureConfig{}, nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return common.AzureConfig{}, nil
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		level.Error(s.logger).Log("req", err)
	}
	var azureInfo common.AzureConfig

	err = json.Unmarshal(bodyBytes, &azureInfo)
	if err != nil {
		level.Error(s.logger).Log("err", err)
	}
	return azureInfo, nil
}
