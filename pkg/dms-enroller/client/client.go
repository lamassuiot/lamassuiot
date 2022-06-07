package lamassuenroller

import (
	"context"
	"encoding/json"

	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
)

type LamassuEnrollerClient interface {
	CreateDMS(ctx context.Context, csrBase64Encoded string, dmsName string) (dto.DMS, error)
	CreateDMSForm(ctx context.Context, subject dto.Subject, PrivateKeyMetadata dto.PrivateKeyMetadata, dmsName string) (string, dto.DMS, error)
	UpdateDMSStatus(ctx context.Context, status string, id string, CAList []string) (dto.DMS, error)
	DeleteDMS(ctx context.Context, id string) error
	GetDMSs(ctx context.Context, queryParameters filters.QueryParameters) (dto.GetDmsResponse, error)
	GetDMSbyID(ctx context.Context, id string) (dto.DMS, error)
}

type LamassuEnrollerClientConfig struct {
	client clientUtils.BaseClient
}

func NewLamassuEnrollerClient(config clientUtils.ClientConfiguration) (LamassuEnrollerClient, error) {
	baseClient, err := clientUtils.NewBaseClient(config)
	if err != nil {
		return nil, err
	}

	return &LamassuEnrollerClientConfig{
		client: baseClient,
	}, nil
}
func (c *LamassuEnrollerClientConfig) CreateDMS(ctx context.Context, csrBase64Encoded string, dmsName string) (dto.DMS, error) {
	body := dto.PostCSRRequest{
		Csr:     csrBase64Encoded,
		DmsName: dmsName,
	}
	req, err := c.client.NewRequest("POST", "v1/"+dmsName+"/form", body)
	if err != nil {
		return dto.DMS{}, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.DMS{}, err
	}
	var dms dto.DMS
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &dms)
	return dms, nil
}
func (c *LamassuEnrollerClientConfig) CreateDMSForm(ctx context.Context, subject dto.Subject, PrivateKeyMetadata dto.PrivateKeyMetadata, dmsName string) (string, dto.DMS, error) {

	body := dto.PostDmsCreationFormRequest{
		DmsName:     dmsName,
		Subject:     subject,
		KeyMetadata: PrivateKeyMetadata,
	}
	req, err := c.client.NewRequest("POST", "v1/"+dmsName+"/form", body)
	if err != nil {
		return "", dto.DMS{}, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return "", dto.DMS{}, err
	}

	var dms dto.DmsCreationResponse

	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &dms)
	return dms.PrivKey, dms.Dms, nil
}
func (c *LamassuEnrollerClientConfig) UpdateDMSStatus(ctx context.Context, status string, id string, CAList []string) (dto.DMS, error) {
	body := dto.PutChangeDmsStatusRequest{
		Status: status,
		CAs:    CAList,
	}
	req, err := c.client.NewRequest("PUT", "v1/"+id, body)
	if err != nil {
		return dto.DMS{}, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.DMS{}, err
	}
	var dms dto.DMS
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &dms)
	return dms, nil
}
func (c *LamassuEnrollerClientConfig) DeleteDMS(ctx context.Context, id string) error {
	req, err := c.client.NewRequest("DELETE", "v1/"+id, nil)
	if err != nil {
		return err
	}
	_, _, err = c.client.Do(req)
	if err != nil {
		return err
	}
	return nil
}
func (c *LamassuEnrollerClientConfig) GetDMSbyID(ctx context.Context, id string) (dto.DMS, error) {
	req, err := c.client.NewRequest("GET", "v1/"+id, nil)
	if err != nil {
		return dto.DMS{}, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.DMS{}, err
	}
	var dms dto.DMS
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &dms)
	return dms, nil
}
func (c *LamassuEnrollerClientConfig) GetDMSs(ctx context.Context, queryParameters filters.QueryParameters) (dto.GetDmsResponse, error) {
	req, err := c.client.NewRequest("GET", "v1/", nil)
	if err != nil {
		return dto.GetDmsResponse{}, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.GetDmsResponse{}, err
	}
	var dmss dto.GetDmsResponse
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &dmss)

	return dmss, nil
}
