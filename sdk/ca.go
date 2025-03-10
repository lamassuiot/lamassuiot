package sdk

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type CAClient services.CAService

type httpCAClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewHttpCAClient(client *http.Client, url string) services.CAService {
	baseURL := url
	return &httpCAClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *httpCAClient) GetCARequests(ctx context.Context, input services.GetItemsInput[models.CACertificateRequest]) (string, error) {
	url := cli.baseUrl + "/v1/cas/requests"
	return IterGet[models.CACertificateRequest, *resources.GetItemsResponse[models.CACertificateRequest]](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	engine, err := Get[[]*models.CryptoEngineProvider](ctx, cli.httpClient, cli.baseUrl+"/v1/engines", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return engine, nil
}

func (cli *httpCAClient) GetStats(ctx context.Context) (*models.CAStats, error) {
	stats, err := Get[*models.CAStats](ctx, cli.httpClient, cli.baseUrl+"/v1/stats", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return stats, nil
}
func (cli *httpCAClient) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	stats, err := Get[map[models.CertificateStatus]int](ctx, cli.httpClient, cli.baseUrl+"/v1/stats/"+input.SubjectKeyID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (cli *httpCAClient) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	url := cli.baseUrl + "/v1/cas"
	return IterGet[models.Certificate, *resources.GetCAsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.Certificate, error) {
	response, err := Get[models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.SubjectKeyID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	url := cli.baseUrl + "/v1/cas/cn/" + input.CommonName
	return IterGet[models.Certificate, *resources.GetCAsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas", resources.CreateCABody{
		Subject:      input.Subject,
		KeyMetadata:  input.KeyMetadata,
		CAExpiration: input.CAExpiration,
		EngineID:     input.EngineID,
		ParentID:     input.ParentID,
		Metadata:     input.Metadata,
	}, map[int][]error{
		400: {
			errs.ErrCAIncompatibleValidity,
		},
		409: {
			errs.ErrCAAlreadyExists,
		},
		500: {
			errs.ErrCAIncompatibleValidity,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) RequestCACSR(ctx context.Context, input services.RequestCAInput) (*models.CACertificateRequest, error) {
	response, err := Post[*models.CACertificateRequest](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/request", resources.CreateCABody{
		Subject:     input.Subject,
		KeyMetadata: input.KeyMetadata,
		EngineID:    input.EngineID,
		Metadata:    input.Metadata,
	}, map[int][]error{
		400: {
			errs.ErrCAIncompatibleValidity,
			errs.ErrCAIssuanceExpiration,
		},
		409: {
			errs.ErrCAAlreadyExists,
		},
		500: {
			errs.ErrCAIncompatibleValidity,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) SignCertificate(ctx context.Context, input services.SignCertificateInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.SubjectKeyID+"/certificates/sign", resources.SignCertificateBody{
		CertRequest: input.CertRequest,
		Profile:     input.IssuanceProfile,
	}, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (*models.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *httpCAClient) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (*models.Certificate, error) {
	cert := models.X509Certificate(*input.Certificate)
	response, err := Post[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/import", resources.ImportCertificateBody{
		Certificate: &cert,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.SubjectKeyID+"/status", resources.UpdateCertificateStatusBody{
		NewStatus:        input.Status,
		RevocationReason: input.RevocationReason,
	}, map[int][]error{
		400: {
			errs.ErrCertificateStatusTransitionNotAllowed,
		},
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (*models.Certificate, error) {
	response, err := Put[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.SubjectKeyID+"/metadata", resources.UpdateCAMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) DeleteCA(ctx context.Context, input services.DeleteCAInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.SubjectKeyID, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
		400: {
			errs.ErrCAStatus,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpCAClient) SignatureSign(ctx context.Context, input services.SignatureSignInput) ([]byte, error) {
	response, err := Post[*resources.SignResponse](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.SubjectKeyID+"/signature/sign", resources.SignatureSignBody{
		Message:          base64.StdEncoding.EncodeToString(input.Message),
		MessageType:      input.MessageType,
		SigningAlgorithm: input.SigningAlgorithm,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.SignedData)
}

func (cli *httpCAClient) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (bool, error) {
	response, err := Post[*resources.VerifyResponse](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.SubjectKeyID+"/signature/verify", resources.SignatureVerifyBody{
		Signature:        base64.StdEncoding.EncodeToString(input.Signature),
		Message:          base64.StdEncoding.EncodeToString(input.Message),
		MessageType:      input.MessageType,
		SigningAlgorithm: input.SigningAlgorithm,
	}, map[int][]error{})
	if err != nil {
		return false, err
	}

	return response.Valid, nil
}

func (cli *httpCAClient) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	response, err := Get[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber, nil, map[int][]error{
		404: {
			errs.ErrCertificateNotFound,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	url := cli.baseUrl + "/v1/certificates"
	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	url := cli.baseUrl + "/v1/cas/" + input.SubjectKeyID + "/certificates"
	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
	})
}

func (cli *httpCAClient) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	url := fmt.Sprintf("%s/v1/certificates/expiration?expires_after=%s&expires_before=%s", cli.baseUrl, input.ExpiresAfter.UTC().Format("2006-01-02T15:04:05Z07:00"), input.ExpiresBefore.UTC().Format("2006-01-02T15:04:05Z07:00"))
	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	url := fmt.Sprintf("%s/v1/cas/%s/certificates/status/%s", cli.baseUrl, input.SubjectKeyID, input.Status)

	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	url := fmt.Sprintf("%s/v1/certificates/status/%s", cli.baseUrl, input.Status)

	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (*models.Certificate, error) {
	response, err := Put[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber+"/status", resources.UpdateCertificateStatusBody{
		NewStatus:        input.NewStatus,
		RevocationReason: input.RevocationReason,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (*models.Certificate, error) {
	response, err := Put[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber+"/metadata", resources.UpdateCertificateMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{
		404: {
			errs.ErrCertificateNotFound,
		},

		400: {
			errs.ErrValidateBadRequest,
		},
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) GetCARequestByID(ctx context.Context, input services.GetByIDInput) (*models.CACertificateRequest, error) {
	response, err := Get[models.CACertificateRequest](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/requests/"+input.ID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) DeleteCARequestByID(ctx context.Context, input services.GetByIDInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/cas/requests/"+input.ID, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}
