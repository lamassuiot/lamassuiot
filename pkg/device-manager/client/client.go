package lamassudevmanager

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	clientFilers "github.com/lamassuiot/lamassuiot/pkg/utils/client/filters"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	filtersTypes "github.com/lamassuiot/lamassuiot/pkg/utils/common/types"
)

// import (
// 	"context"
// 	"crypto/x509"
// 	"encoding/json"

// 	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
// 	clientFilters "github.com/lamassuiot/lamassuiot/pkg/utils/client/filters"
// 	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

// 	lamassuEstClient "github.com/lamassuiot/lamassuiot/pkg/est/client"
// )

type LamassuDeviceManagerClient interface {
	IterateDevicesbyDMSWithPredicate(ctx context.Context, input *api.IterateDevicesByDMSWithPredicateInput) (*api.IterateDevicesByDMSWithPredicateOutput, error)
	CreateDevice(ctx context.Context, alias string, deviceID string, dmsName string, description string, tags []string, iconName string, iconColor string) (*api.Device, error)
	// 	UpdateDeviceById(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) (dto.Device, error)
	GetDevices(ctx context.Context, input *api.GetDevicesInput) (*api.GetDevicesOutput, error)
	GetDeviceById(ctx context.Context, deviceId string) (*api.GetDeviceByIdOutput, error)
	// 	GetDevicesByDMS(ctx context.Context, dmsId string, queryParameters filters.QueryParameters) (dto.GetDevicesResponse, error)
	// 	DeleteDevice(ctx context.Context, id string) error
	// 	RevokeDeviceCert(ctx context.Context, id string, revocationReason string) error
	// 	GetDeviceLogs(ctx context.Context, id string) (dto.GetLogsResponse, error)
	// 	GetDeviceCert(ctx context.Context, id string) (dto.DeviceCert, error)
	// 	GetDeviceCertHistory(ctx context.Context, id string) ([]dto.DeviceCertHistory, error)
	// 	GetDmsCertHistoryThirtyDays(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DMSCertHistory, error)
	// 	GetDmsLastIssuedCert(ctx context.Context, queryParameters filters.QueryParameters) (dto.GetLastIssuedCertResponse, error)

	// //EST Endpoints
	// CACerts(ctx context.Context, aps string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool, estServerAddr string) ([]*x509.Certificate, error)
	// Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool, estServerAddr string) (dto.Enroll, error)
	// Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool, estServerAddr string) (dto.Enroll, error)
	// ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool, estServerAddr string) (dto.ServerKeyGen, error)
}

type LamassuDeviceManagerClientConfig struct {
	client clientUtils.BaseClient
}

func NewLamassuDeviceManagerClient(config clientUtils.BaseClientConfigurationuration) (LamassuDeviceManagerClient, error) {
	baseClient, err := clientUtils.NewBaseClient(config)
	if err != nil {
		return nil, err
	}

	return &LamassuDeviceManagerClientConfig{
		client: baseClient,
	}, nil
}

func (c *LamassuDeviceManagerClientConfig) CreateDevice(ctx context.Context, alias string, deviceID string, dmsName string, description string, tags []string, iconName string, iconColor string) (*api.Device, error) {
	body := struct {
		DeviceID    string   `json:"id"`
		Alias       string   `json:"alias"`
		DmsName     string   `json:"dms_name"`
		Tags        []string `json:"tags"`
		Description string   `json:"description"`
		IconColor   string   `json:"icon_color"`
		IconName    string   `json:"icon_name"`
	}{
		DeviceID:    deviceID,
		Alias:       alias,
		DmsName:     dmsName,
		Tags:        tags,
		Description: description,
		IconColor:   iconColor,
		IconName:    iconName,
	}

	req, err := c.client.NewRequest(ctx, "POST", "v1/devices", body)
	if err != nil {
		return nil, err
	}
	respBody, err := c.client.Do2(req)
	if err != nil {
		return nil, err
	}
	var device api.Device
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &device)
	return &device, nil
}

func (c *LamassuDeviceManagerClientConfig) IterateDevicesbyDMSWithPredicate(ctx context.Context, input *api.IterateDevicesByDMSWithPredicateInput) (*api.IterateDevicesByDMSWithPredicateOutput, error) {
	limit := 100
	i := 0

	var devices []api.Device = make([]api.Device, 0)
	for {
		getDevicessOutput, err := c.GetDevicesByDMS(
			ctx,
			&api.GetDevicesByDMSInput{
				DmsName: input.DmsName,
				QueryParameters: common.QueryParameters{
					Filters: []filtersTypes.Filter{},
					Sort:    common.SortOptions{},
					Pagination: common.PaginationOptions{
						Limit:  i,
						Offset: i * limit,
					},
				},
			},
		)
		if err != nil {
			return &api.IterateDevicesByDMSWithPredicateOutput{}, errors.New("could not get Devices")
		}

		if len(getDevicessOutput.Devices) == 0 {
			break
		}

		devices = append(devices, getDevicessOutput.Devices...)
		i++
	}
	for _, device := range devices {
		input.PredicateFunc(&device)
	}

	return &api.IterateDevicesByDMSWithPredicateOutput{}, nil
}

// func (c *LamassuDeviceManagerClientConfig) UpdateDeviceById(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) (dto.Device, error) {
// 	body := dto.UpdateDevicesByIdRequest{
// 		DeviceID:    deviceID,
// 		Alias:       alias,
// 		Description: description,
// 		Tags:        tags,
// 		IconName:    iconName,
// 		IconColor:   iconColor,
// 		DmsId:       dmsID,
// 	}
// 	req, err := c.client.NewRequest(ctx, "PUT", "v1/devices/"+deviceID, body)
// 	if err != nil {
// 		return dto.Device{}, err
// 	}
// 	respBody, _, err := c.client.Do(req)
// 	if err != nil {
// 		return dto.Device{}, err
// 	}
// 	var device dto.Device
// 	jsonString, _ := json.Marshal(respBody)
// 	json.Unmarshal(jsonString, &device)
// 	return device, nil
// }

func (c *LamassuDeviceManagerClientConfig) GetDevices(ctx context.Context, input *api.GetDevicesInput) (*api.GetDevicesOutput, error) {
	urlParams := clientFilers.GenerateHttpQueryParams(input.QueryParameters)
	req, err := c.client.NewRequest(ctx, "GET", "v1/devices", nil)
	if err != nil {
		return &api.GetDevicesOutput{}, err
	}

	req.URL.RawQuery = urlParams
	var output api.GetDevicesOutputSerialized
	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.GetDevicesOutput{}, err
	}
	deserialized := output.Deserialize()

	return &deserialized, nil
}

func (c *LamassuDeviceManagerClientConfig) GetDevicesByDMS(ctx context.Context, input *api.GetDevicesByDMSInput) (*api.GetDevicesByDMSOutput, error) {
	urlParams := clientFilers.GenerateHttpQueryParams(input.QueryParameters)
	req, err := c.client.NewRequest(ctx, "GET", "v1/devices/dms/"+input.DmsName, nil)
	if err != nil {
		return &api.GetDevicesByDMSOutput{}, err
	}

	req.URL.RawQuery = urlParams
	var output api.GetDevicesByDMSOutputSerialized
	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.GetDevicesByDMSOutput{}, err
	}
	deserialized := output.Deserialize()

	return &deserialized, nil
}

func (c *LamassuDeviceManagerClientConfig) GetDeviceById(ctx context.Context, deviceId string) (*api.GetDeviceByIdOutput, error) {
	req, err := c.client.NewRequest(ctx, "GET", "v1/devices/"+deviceId, nil)
	if err != nil {
		return &api.GetDeviceByIdOutput{}, err
	}
	var output api.GetDeviceByIdOutputSerialized
	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.GetDeviceByIdOutput{}, err
	}
	deserialized := output.Deserialize()

	return &deserialized, nil
}

// func (c *LamassuDeviceManagerClientConfig) GetDevicesByDMS(ctx context.Context, dmsId string, queryParameters filters.QueryParameters) (dto.GetDevicesResponse, error) {
// 	var newParams string
// 	req, err := c.client.NewRequest(ctx, "GET", "v1/devices/dms/"+dmsId, nil)
// 	if err != nil {
// 		return dto.GetDevicesResponse{}, err
// 	}

// 	newParams = clientFilters.GenerateHttpQueryParams(queryParameters)

// 	req.URL.RawQuery = newParams
// 	respBody, _, err := c.client.Do(req)
// 	if err != nil {
// 		return dto.GetDevicesResponse{}, err
// 	}
// 	var resp dto.GetDevicesResponse

// 	jsonString, _ := json.Marshal(respBody)
// 	json.Unmarshal(jsonString, &resp)
// 	return resp, nil
// }
// func (c *LamassuDeviceManagerClientConfig) DeleteDevice(ctx context.Context, id string) error {
// 	req, err := c.client.NewRequest(ctx, "DELETE", "v1/devices/"+id, nil)
// 	if err != nil {
// 		return err
// 	}
// 	_, _, err = c.client.Do(req)
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }
// func (c *LamassuDeviceManagerClientConfig) RevokeDeviceCert(ctx context.Context, id string, revocationReason string) error {
// 	req, err := c.client.NewRequest(ctx, "DELETE", "v1/devices/"+id+"/revoke", nil)
// 	if err != nil {
// 		return err
// 	}
// 	_, _, err = c.client.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
// func (c *LamassuDeviceManagerClientConfig) GetDeviceLogs(ctx context.Context, id string) (dto.GetLogsResponse, error) {
// 	req, err := c.client.NewRequest(ctx, "GET", "v1/devices/"+id+"/logs", nil)
// 	if err != nil {
// 		return dto.GetLogsResponse{}, err
// 	}
// 	respBody, _, err := c.client.Do(req)
// 	if err != nil {
// 		return dto.GetLogsResponse{}, err
// 	}

// 	var logs dto.GetLogsResponse
// 	jsonString, _ := json.Marshal(respBody)
// 	json.Unmarshal(jsonString, &logs)
// 	return logs, nil
// }
// func (c *LamassuDeviceManagerClientConfig) GetDeviceCert(ctx context.Context, id string) (dto.DeviceCert, error) {
// 	req, err := c.client.NewRequest(ctx, "GET", "v1/devices/"+id+"/cert", nil)
// 	if err != nil {
// 		return dto.DeviceCert{}, err
// 	}
// 	respBody, _, err := c.client.Do(req)
// 	if err != nil {
// 		return dto.DeviceCert{}, err
// 	}

// 	var cert dto.DeviceCert
// 	jsonString, _ := json.Marshal(respBody)
// 	json.Unmarshal(jsonString, &cert)

// 	return cert, nil
// }
// func (c *LamassuDeviceManagerClientConfig) GetDeviceCertHistory(ctx context.Context, id string) ([]dto.DeviceCertHistory, error) {
// 	req, err := c.client.NewRequest(ctx, "GET", "v1/devices/"+id+"/cert-history", nil)
// 	if err != nil {
// 		return []dto.DeviceCertHistory{}, err
// 	}
// 	respBody, _, err := c.client.Do(req)
// 	if err != nil {
// 		return []dto.DeviceCertHistory{}, err
// 	}

// 	logsArrayInterface := respBody.([]interface{})
// 	var certHistory []dto.DeviceCertHistory
// 	for _, item := range logsArrayInterface {
// 		history := dto.DeviceCertHistory{}
// 		jsonString, _ := json.Marshal(item)
// 		json.Unmarshal(jsonString, &history)
// 		certHistory = append(certHistory, history)
// 	}
// 	return certHistory, nil
// }
// func (c *LamassuDeviceManagerClientConfig) GetDmsCertHistoryThirtyDays(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DMSCertHistory, error) {
// 	var newParams string
// 	req, err := c.client.NewRequest(ctx, "GET", "v1/devices/dms-cert-history/thirty-days", nil)
// 	if err != nil {
// 		return []dto.DMSCertHistory{}, err
// 	}

// 	newParams = clientFilters.GenerateHttpQueryParams(queryParameters)

// 	req.URL.RawQuery = newParams
// 	respBody, _, err := c.client.Do(req)
// 	if err != nil {
// 		return []dto.DMSCertHistory{}, err
// 	}

// 	dmsCertHistArrayInterface := respBody.([]interface{})
// 	var dmsCertHistory []dto.DMSCertHistory
// 	for _, item := range dmsCertHistArrayInterface {
// 		history := dto.DMSCertHistory{}
// 		jsonString, _ := json.Marshal(item)
// 		json.Unmarshal(jsonString, &history)
// 		dmsCertHistory = append(dmsCertHistory, history)
// 	}
// 	return dmsCertHistory, nil
// }
// func (c *LamassuDeviceManagerClientConfig) GetDmsLastIssuedCert(ctx context.Context, queryParameters filters.QueryParameters) (dto.GetLastIssuedCertResponse, error) {
// 	var newParams string
// 	req, err := c.client.NewRequest(ctx, "GET", "v1/devices/dms-cert-history/last-issued", nil)
// 	if err != nil {
// 		return dto.GetLastIssuedCertResponse{}, err
// 	}

// 	newParams = clientFilters.GenerateHttpQueryParams(queryParameters)

// 	req.URL.RawQuery = newParams
// 	respBody, _, err := c.client.Do(req)
// 	if err != nil {
// 		return dto.GetLastIssuedCertResponse{}, err
// 	}

// 	var dmsLastIssued dto.GetLastIssuedCertResponse
// 	jsonString, _ := json.Marshal(respBody)
// 	json.Unmarshal(jsonString, &dmsLastIssued)
// 	return dmsLastIssued, nil
// }
// func (c *LamassuDeviceManagerClientConfig) CACerts(ctx context.Context, aps string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool, estServerAddr string) ([]*x509.Certificate, error) {
// 	estClient, err := lamassuEstClient.NewLamassuEstClient(estServerAddr, serverCert, clientCert, clientKey, nil)
// 	cas, err := estClient.CACerts(ctx)
// 	if err != nil {
// 		return []*x509.Certificate{}, err
// 	}
// 	return cas, nil
// }
// func (c *LamassuDeviceManagerClientConfig) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool, estServerAddr string) (dto.Enroll, error) {
// 	estClient, err := lamassuEstClient.NewLamassuEstClient(estServerAddr, serverCert, clientCert, clientKey, nil)
// 	if err != nil {
// 		return dto.Enroll{}, err
// 	}
// 	crt, err := estClient.Enroll(ctx, aps, csr)
// 	if err != nil {
// 		return dto.Enroll{}, err
// 	}
// 	var enroll dto.Enroll
// 	enroll.Cert = crt
// 	//enroll.CaCert = cacrt
// 	return enroll, nil
// }
// func (c *LamassuDeviceManagerClientConfig) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool, estServerAddr string) (dto.Enroll, error) {
// 	estClient, err := lamassuEstClient.NewLamassuEstClient(estServerAddr, serverCert, clientCert, clientKey, nil)
// 	if err != nil {
// 		return dto.Enroll{}, err
// 	}
// 	crt, err := estClient.Reenroll(ctx, csr)
// 	if err != nil {
// 		return dto.Enroll{}, err
// 	}
// 	var reenroll dto.Enroll
// 	reenroll.Cert = crt
// 	//reenroll.CaCert = cacrt
// 	return reenroll, nil
// }
// func (c *LamassuDeviceManagerClientConfig) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool, estServerAddr string) (dto.ServerKeyGen, error) {
// 	estClient, err := lamassuEstClient.NewLamassuEstClient(estServerAddr, serverCert, clientCert, clientKey, nil)
// 	if err != nil {
// 		return dto.ServerKeyGen{}, err
// 	}
// 	crt, key, err := estClient.ServerKeyGen(ctx, aps, csr)
// 	if err != nil {
// 		return dto.ServerKeyGen{}, err
// 	}
// 	var serverkeygen dto.ServerKeyGen
// 	serverkeygen.Cert = crt
// 	//serverkeygen.CaCert = cacrt
// 	serverkeygen.Key = key
// 	return serverkeygen, nil
// }
