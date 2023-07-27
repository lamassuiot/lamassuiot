package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	clientFilers "github.com/lamassuiot/lamassuiot/pkg/utils/client/filters"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

//TODO: check all clients implementations and test them

const (
	//Generic Errors
	ErrValidationError = "validation error"

	//Specific Errors
	ErrCADoesNotExist           = "CA does not exist"
	ErrCAAlreadyRevoked         = "CA already revoked"
	ErrDuplicateCA              = "duplicate CA"
	ErrCertificateDoesNotExist  = "certificate does not exist"
	ErrCerificateAlreadyRevoked = "certificate already revoked"
)

type LamassuCAClient interface {
	service.Service
}

type lamassuCaClientConfig struct {
	client clientUtils.BaseClient
}

func NewLamassuCAClient(config clientUtils.BaseClientConfigurationuration) (LamassuCAClient, error) {
	baseClient, err := clientUtils.NewBaseClient(config)
	if err != nil {
		return nil, err
	}

	return &lamassuCaClientConfig{
		client: baseClient,
	}, nil
}

func (c *lamassuCaClientConfig) Health() bool {
	//TODO: To Implement
	return true
}

func (c *lamassuCaClientConfig) GetEngineProviderInfo() api.EngineProviderInfo {
	//TODO: To Implement
	return api.EngineProviderInfo{}
}

func (c *lamassuCaClientConfig) Stats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error) {
	//TODO: To Implement
	return &api.GetStatsOutput{}, nil
}

func (c *lamassuCaClientConfig) GetCAs(ctx context.Context, input *api.GetCAsInput) (*api.GetCAsOutput, error) {
	urlParams := clientFilers.GenerateHttpQueryParams(input.QueryParameters)
	var output api.GetCAsOutputSerialized
	_, err := newClient(c.client).Do(ctx, "GET", fmt.Sprintf("v1/%s", input.CAType), urlParams, nil).GetDeserializedResponse(&output)
	deserialized := output.Deserialize()
	return &deserialized, err
}

func (c *lamassuCaClientConfig) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (*api.GetCAByNameOutput, error) {
	var output api.GetCAByNameOutputSerialized
	_, err := newClient(c.client).Do(ctx, "GET", fmt.Sprintf("v1/%s/%s", input.CAType, input.CAName), "", nil).GetDeserializedResponse(&output)
	deserialized := output.Deserialize()
	return &deserialized, err
}
func (c *lamassuCaClientConfig) DeleteCA(ctx context.Context, input *api.GetCAByNameInput) error {
	return nil
}
func (c *lamassuCaClientConfig) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (*api.IterateCAsWithPredicateOutput, error) {
	limit := 100
	i := 0

	var cas []api.CACertificate = make([]api.CACertificate, 0)

	for {
		getCAsOutput, err := c.GetCAs(ctx, &api.GetCAsInput{
			CAType: api.CATypePKI,
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  i,
					Offset: i * limit,
				},
			},
		})
		if err != nil {
			return &api.IterateCAsWithPredicateOutput{}, errors.New("could not get CAs")
		}

		if len(getCAsOutput.CAs) == 0 {
			break
		}

		cas = append(cas, getCAsOutput.CAs...)
		i++
	}

	for _, ca := range cas {
		input.PredicateFunc(&ca)
	}

	return &api.IterateCAsWithPredicateOutput{}, nil
}

func (c *lamassuCaClientConfig) CreateCA(ctx context.Context, input *api.CreateCAInput) (*api.CreateCAOutput, error) {
	//TODO: To Refact with new synta. Check GetCAByName and GetCAs
	var caExpiration, issuanceExpiration string
	if input.IssuanceExpirationType == api.ExpirationTypeDate {
		caExpiration = fmt.Sprintf("%d%02d%02dT%02d%02d%dZ", input.CAExpiration.Year(), input.CAExpiration.Month(), input.CAExpiration.Day(), input.CAExpiration.Hour(), input.CAExpiration.Minute(), input.CAExpiration.Second())
		issuanceExpiration = fmt.Sprintf("%d%02d%02dT%02d%02d%dZ", input.IssuanceExpirationDate.Year(), input.IssuanceExpirationDate.Month(), input.IssuanceExpirationDate.Day(), input.IssuanceExpirationDate.Hour(), input.IssuanceExpirationDate.Minute(), input.IssuanceExpirationDate.Second())
	} else {
		caExpiration = fmt.Sprintf("%d", input.CAExpiration.Unix()-time.Now().Unix())
		issuanceExpiration = fmt.Sprintf("%d", int64(*input.IssuanceExpirationDuration))
	}
	body := api.CreateCAPayload{
		KeyMetadata: api.CreacteCAKeyMetadataSubject{
			KeyType: string(input.KeyMetadata.KeyType),
			KeyBits: input.KeyMetadata.KeyBits,
		},
		Subject: api.CreateCASubjectPayload{
			CommonName:       input.Subject.CommonName,
			Country:          input.Subject.Country,
			State:            input.Subject.State,
			Locality:         input.Subject.Locality,
			Organization:     input.Subject.Organization,
			OrganizationUnit: input.Subject.OrganizationUnit,
		},
		IssuanceExpirationType: string(input.IssuanceExpirationType),
		CAExpiration:           caExpiration,
		IssuanceExpiration:     issuanceExpiration,
	}

	req, err := c.client.NewRequest(ctx, "POST", "v1/pki", body)

	if err != nil {
		return &api.CreateCAOutput{}, err
	}

	var output api.CreateCAOutputSerialized
	resp, err := c.client.Do(req, &output)

	if err != nil {
		if resp != nil {
			if resp.StatusCode == http.StatusConflict {
				return &api.CreateCAOutput{}, errors.New(ErrDuplicateCA)
			}
		} else {
			return &api.CreateCAOutput{}, err
		}

		return &api.CreateCAOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuCaClientConfig) ImportCA(ctx context.Context, input *api.ImportCAInput) (*api.ImportCAOutput, error) {
	// 	crtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: input.Certificate.Raw})
	// 	base64CrtContent := base64.StdEncoding.EncodeToString(crtBytes)
	// 	privKeyString, _ := input.PrivateKey.GetPEMString()
	// 	base64CKeyContent := base64.StdEncoding.EncodeToString([]byte(privKeyString))

	// 	body := struct {
	// 		IssuanceDuration int    `json:"issuance_duration"`
	// 		Certificate      string `json:"certificate"`
	// 		PrivateKey       string `json:"private_key"`
	// 	}{
	// 		Certificate:      base64CrtContent,
	// 		PrivateKey:       base64CKeyContent,
	// 		IssuanceDuration: int(input.IssuanceDuration.Hours()),
	// 	}

	// 	req, err := c.client.NewRequest(ctx, "POST", "v1/"+string(input.CAType)+"/import/"+string(input.Certificate.Subject.CommonName), body)
	// 	if err != nil {
	// 		return &api.ImportCAOutput{}, err
	// 	}

	// 	var output api.ImportCAOutput
	// 	_, err = c.client.Do(req, &output)
	// 	if err != nil {
	// 		return &output, err
	// 	}

	// return &output, err
	return &api.ImportCAOutput{}, nil
}

func (c *lamassuCaClientConfig) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (*api.RevokeCAOutput, error) {
	//TODO: To Refact with new synta. Check GetCAByName and GetCAs
	body := api.RevokeCAPayload{
		RevocationReason: input.RevocationReason,
	}

	req, err := c.client.NewRequest(ctx, "DELETE", "v1/"+string(input.CAType)+"/"+input.CAName, body)
	if err != nil {
		return &api.RevokeCAOutput{}, err
	}

	var output api.RevokeCAOutputSerialized
	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.RevokeCAOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuCaClientConfig) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	// TODO: To implement
	return &api.UpdateCAStatusOutput{}, nil
}

func (c *lamassuCaClientConfig) GetExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.GetExpiredAndOutOfSyncCertificatesInput) (*api.GetExpiredAndOutOfSyncCertificatesOutput, error) {
	// TODO: To implement
	return &api.GetExpiredAndOutOfSyncCertificatesOutput{}, nil
}

func (c *lamassuCaClientConfig) GetCertificatesAboutToExpire(ctx context.Context, input *api.GetCertificatesAboutToExpireInput) (*api.GetCertificatesAboutToExpireOutput, error) {
	// TODO: To implement
	return &api.GetCertificatesAboutToExpireOutput{}, nil
}

func (c *lamassuCaClientConfig) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (*api.SignCertificateRequestOutput, error) {
	//TODO: To Refact with new synta. Check GetCAByName and GetCAs
	var certificateExpiration string
	if input.ExpirationType == api.ExpirationTypeDate {
		certificateExpiration = fmt.Sprintf("%d%02d%02dT%02d%02d%dZ", input.CertificateExpiration.Year(), input.CertificateExpiration.Month(), input.CertificateExpiration.Day(), input.CertificateExpiration.Hour(), input.CertificateExpiration.Minute(), input.CertificateExpiration.Second())
	} else if input.ExpirationType == api.ExpirationTypeDuration {
		certificateExpiration = fmt.Sprintf("%d", input.CertificateExpiration.Unix()-time.Now().Unix())
	}
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: input.CertificateSigningRequest.Raw})
	base64CsrContent := base64.StdEncoding.EncodeToString(csrBytes)

	body := api.SignCertificateRequestPayload{
		CertificateRequest:    base64CsrContent,
		CommonName:            input.CommonName,
		SignVerbatim:          input.SignVerbatim,
		ExpirationType:        string(input.ExpirationType),
		CertificateExpiration: certificateExpiration,
	}
	req, err := c.client.NewRequest(ctx, "POST", "v1/"+string(input.CAType)+"/"+input.CAName+"/sign", body)

	if err != nil {
		return &api.SignCertificateRequestOutput{}, err
	}

	var output api.SignCertificateRequestOutputSerialized
	_, err = c.client.Do(req, &output)

	if err != nil {
		return &api.SignCertificateRequestOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuCaClientConfig) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (*api.RevokeCertificateOutput, error) {
	//TODO: To Refact with new synta. Check GetCAByName and GetCAs

	body := api.RevokeCertificatePayload{
		RevocationReason: input.RevocationReason,
	}

	req, err := c.client.NewRequest(ctx, "DELETE", "v1/"+string(input.CAType)+"/"+input.CAName+"/certificates/"+input.CertificateSerialNumber, body)
	if err != nil {
		return &api.RevokeCertificateOutput{}, nil
	}

	var output api.RevokeCertificateOutputSerialized
	response, err := c.client.Do(req, &output)
	if response.StatusCode == 409 {
		return &api.RevokeCertificateOutput{}, &AlreadyRevokedError{
			CaName:       input.CAName,
			SerialNumber: input.CertificateSerialNumber,
		}
	} else if err != nil {
		return &api.RevokeCertificateOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuCaClientConfig) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (*api.UpdateCertificateStatusOutput, error) {
	// TODO: To implement
	return &api.UpdateCertificateStatusOutput{}, nil
}

func (c *lamassuCaClientConfig) ScanAboutToExpireCertificates(ctx context.Context, input *api.ScanAboutToExpireCertificatesInput) (*api.ScanAboutToExpireCertificatesOutput, error) {
	// TODO: To implement
	return &api.ScanAboutToExpireCertificatesOutput{}, nil
}

func (c *lamassuCaClientConfig) Verify(ctx context.Context, input *api.VerifyInput) (*api.VerifyOutput, error) {
	// TODO: To implement
	return &api.VerifyOutput{}, nil
}

func (c *lamassuCaClientConfig) Sign(ctx context.Context, input *api.SignInput) (*api.SignOutput, error) {
	// TODO: To implement
	return &api.SignOutput{}, nil
}

func (c *lamassuCaClientConfig) ScanExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.ScanExpiredAndOutOfSyncCertificatesInput) (*api.ScanExpiredAndOutOfSyncCertificatesOutput, error) {
	// TODO: To implement
	return &api.ScanExpiredAndOutOfSyncCertificatesOutput{}, nil
}

func (c *lamassuCaClientConfig) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (*api.GetCertificateBySerialNumberOutput, error) {
	//TODO: To Refact with new synta. Check GetCAByName and GetCAs

	req, err := c.client.NewRequest(ctx, "GET", "v1/"+string(input.CAType)+"/"+input.CAName+"/certificates/"+input.CertificateSerialNumber, nil)
	if err != nil {
		return &api.GetCertificateBySerialNumberOutput{}, err
	}

	var output api.GetCertificateBySerialNumberOutputSerialized
	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.GetCertificateBySerialNumberOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuCaClientConfig) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (*api.GetCertificatesOutput, error) {
	//TODO: To Refact with new synta. Check GetCAByName and GetCAs

	req, err := c.client.NewRequest(ctx, "GET", "v1/"+string(input.CAType)+"/"+input.CAName+"/issued", nil)
	if err != nil {
		return &api.GetCertificatesOutput{}, err
	}

	newParams := clientFilers.GenerateHttpQueryParams(input.QueryParameters)
	req.URL.RawQuery = newParams

	var output api.GetCertificatesOutputSerialized
	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.GetCertificatesOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuCaClientConfig) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (*api.IterateCertificatesWithPredicateOutput, error) {
	limit := 100
	i := 0

	var certs []api.Certificate = make([]api.Certificate, 0)

	for {
		getCAsOutput, err := c.GetCertificates(ctx, &api.GetCertificatesInput{
			CAType: api.CATypePKI,
			CAName: input.CAName,
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  i,
					Offset: i * limit,
				},
			},
		})
		if err != nil {
			return &api.IterateCertificatesWithPredicateOutput{}, errors.New("could not get Certificates")
		}

		if len(getCAsOutput.Certificates) == 0 {
			break
		}
		certs = append(certs, getCAsOutput.Certificates...)
		i++
	}

	for _, cert := range certs {
		input.PredicateFunc(&cert)
	}

	return &api.IterateCertificatesWithPredicateOutput{}, nil
}

type genericRequest struct {
	client clientUtils.BaseClient
}

type genericResponse struct {
	err      error
	response *http.Response
}

func newClient(client clientUtils.BaseClient) *genericRequest {
	return &genericRequest{
		client: client,
	}
}

func (greq *genericRequest) Do(ctx context.Context, method string, path string, queryParameters string, body interface{}) *genericResponse {
	req, err := greq.client.NewRequest(ctx, method, path, body)
	if queryParameters != "" {
		req.URL.RawQuery = queryParameters
	}

	if err != nil {
		return &genericResponse{err: err}
	}

	resp, err := greq.client.Do2(req)

	if err != nil {
		return &genericResponse{err: err}
	}

	return &genericResponse{
		response: resp,
	}
}

func (gr *genericResponse) GetDeserializedResponse(output any) (*http.Response, error) {
	if gr.err != nil {
		return gr.response, gr.err
	}

	err := json.NewDecoder(gr.response.Body).Decode(&output)
	if err != nil {
		return nil, err
	}

	return gr.response, nil
}

type AlreadyRevokedError struct {
	CaName       string
	SerialNumber string
}
type AlreadyRevokedCAError struct {
	CaName string
}

func (e *AlreadyRevokedError) Error() string {
	return fmt.Sprintf("certificate already revoked. CA name=%s Cert Serial Number=%s", e.CaName, e.SerialNumber)
}

func (e *AlreadyRevokedCAError) Error() string {
	return fmt.Sprintf("CA already revoked: %s", e.CaName)
}
