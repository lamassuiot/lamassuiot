package clients

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
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

func (cli *httpCAClient) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	url := cli.baseUrl + "/v1/cas"

	if input.ExhaustiveRun {
		err := IterGet[models.CACertificate, *resources.GetCAsResponse](ctx, cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](ctx, cli.httpClient, url, input.QueryParameters, map[int][]error{})
		for _, elem := range resp.IterableList.List {
			input.ApplyFunc(elem)
		}
		return resp.NextBookmark, err
	}

}

func (cli *httpCAClient) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	response, err := Get[models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	url := cli.baseUrl + "/v1/cas/cn/" + input.CommonName

	if input.ExhaustiveRun {
		err := IterGet[models.CACertificate, *resources.GetCAsResponse](ctx, cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](ctx, cli.httpClient, url, input.QueryParameters, map[int][]error{})
		for _, elem := range resp.IterableList.List {
			input.ApplyFunc(elem)
		}
		return resp.NextBookmark, err
	}

}

func (cli *httpCAClient) GetCABySerialNumber(ctx context.Context, input services.GetCABySerialNumberInput) (*models.CACertificate, error) {
	url := cli.baseUrl + "/v1/cas/sn/" + input.SerialNumber

	resp, err := Get[models.CACertificate](ctx, cli.httpClient, url, nil, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
	})
	return &resp, err
}

func (cli *httpCAClient) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas", resources.CreateCABody{
		ID:                 input.ID,
		Subject:            input.Subject,
		KeyMetadata:        input.KeyMetadata,
		IssuanceExpiration: input.IssuanceExpiration,
		CAExpiration:       input.CAExpiration,
		EngineID:           input.EngineID,
	}, map[int][]error{
		400: {
			errs.ErrCAIncompatibleExpirationTimeRef,
			errs.ErrCAIssuanceExpiration,
		},
		409: {
			errs.ErrCAAlreadyExists,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) ImportCA(ctx context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	var privKey string
	if input.KeyType == models.KeyType(x509.RSA) {
		rsaBytes := x509.MarshalPKCS1PrivateKey(input.CARSAKey)
		privKey = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: rsaBytes,
		}))
	} else if input.KeyType == models.KeyType(x509.ECDSA) {
		ecBytes, err := x509.MarshalECPrivateKey(input.CAECKey)
		if err != nil {
			return nil, err
		}
		privKey = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecBytes,
		}))
	}

	response, err := Post[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/import", resources.ImportCABody{
		CAType:             models.CertificateType(input.CAType),
		IssuanceExpiration: input.IssuanceExpiration,
		CACertificate:      input.CACertificate,
		CAChain:            input.CAChain,
		CAPrivateKey:       privKey,
		EngineID:           input.EngineID,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) SignCertificate(ctx context.Context, input services.SignCertificateInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/certificates/sign", resources.SignCertificateBody{
		SignVerbatim: input.SignVerbatim,
		CertRequest:  input.CertRequest,
		Subject:      input.Subject,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (*models.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *httpCAClient) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (*models.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *httpCAClient) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/status", resources.UpdateCertificateStatusBody{
		NewStatus:        input.Status,
		RevocationReason: input.RevocationReason,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (*models.CACertificate, error) {
	response, err := Put[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/metadata", resources.UpdateCAMetadataBody{
		Metadata: input.Metadata,
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
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID, map[int][]error{
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
	response, err := Post[*resources.SignResponse](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/signature/sign", resources.SignatureSignBody{
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
	response, err := Post[*resources.VerifyResponse](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/signature/verify", resources.SignatureVerifyBody{
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
	response, err := Get[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	url := cli.baseUrl + "/v1/certificates"

	if input.ExhaustiveRun {
		err := IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetCertsResponse](ctx, cli.httpClient, url, input.QueryParameters, map[int][]error{})
		for _, elem := range resp.IterableList.List {
			input.ApplyFunc(elem)
		}
		return resp.NextBookmark, err
	}
}

func (cli *httpCAClient) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	url := cli.baseUrl + "/v1/cas/" + input.CAID + "/certificates"

	if input.ExhaustiveRun {
		err := IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{
			404: {
				errs.ErrCANotFound,
			},
		})
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](ctx, cli.httpClient, url, input.QueryParameters, map[int][]error{
			404: {
				errs.ErrCANotFound,
			},
		})
		for _, elem := range resp.IterableList.List {
			input.ApplyFunc(&elem.Certificate)
		}
		return resp.NextBookmark, err
	}
}

func (cli *httpCAClient) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	url := fmt.Sprintf("%s/v1/certificates/expiration?expires_after=%s&expires_before=%s", cli.baseUrl, input.ExpiresAfter.UTC().Format("2006-01-02T15:04:05Z07:00"), input.ExpiresBefore.UTC().Format("2006-01-02T15:04:05Z07:00"))

	if input.ExhaustiveRun {
		err := IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](ctx, cli.httpClient, url, input.QueryParameters, map[int][]error{})
		for _, elem := range resp.IterableList.List {
			input.ApplyFunc(&elem.Certificate)
		}
		return resp.NextBookmark, err
	}
}
func (cli *httpCAClient) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	url := fmt.Sprintf("%s/v1/cas/%s/certificates/status/%s", cli.baseUrl, input.CAID, input.Status)

	if input.ExhaustiveRun {
		err := IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.QueryParameters, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](ctx, cli.httpClient, url, input.QueryParameters, map[int][]error{})
		for _, elem := range resp.IterableList.List {
			input.ApplyFunc(&elem.Certificate)
		}
		return resp.NextBookmark, err
	}
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
		Metadata: input.Metadata,
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
