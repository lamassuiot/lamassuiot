package transport

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common/types"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

	httptransport "github.com/go-kit/kit/transport/http"
	lamassuErrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
)

type errorer interface {
	error() error
}

func InvalidJsonFormat() error {
	return &lamassuErrors.GenericError{
		Message:    "Invalid JSON format",
		StatusCode: 400,
	}
}

func InvalidExpirationType() error {
	return &lamassuErrors.GenericError{
		Message:    "Invalid Expiration Type",
		StatusCode: 400,
	}
}

func InvalidCaType() error {
	return &lamassuErrors.GenericError{
		Message:    "Invalid CA Type",
		StatusCode: 400,
	}
}

func filtrableCAModelFields() map[string]types.Filter {
	fieldFiltersMap := make(map[string]types.Filter)
	fieldFiltersMap["status"] = &types.StringFilterField{}
	fieldFiltersMap["serial_number"] = &types.StringFilterField{}
	fieldFiltersMap["ca_name"] = &types.StringFilterField{}
	fieldFiltersMap["valid_from"] = &types.DatesFilterField{}
	fieldFiltersMap["valid_to"] = &types.DatesFilterField{}
	return fieldFiltersMap
}

func MakeHTTPHandler(s service.Service) http.Handler {
	r := mux.NewRouter()
	e := endpoint.MakeServerEndpoints(s)
	options := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(encodeError),
	}

	r.Methods("GET").Path("/health").Handler(
		httptransport.NewServer(
			e.HealthEndpoint,
			decodeHealthRequest,
			encodeHealthResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/cryptoengine").Handler(
		httptransport.NewServer(
			e.GetCryptoEngine,
			decodeCryptoEngineRequest,
			encodeCryptoEngineResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/stats").Handler(
		httptransport.NewServer(
			e.StatsEndpoint,
			decodeStatsRequest,
			encodeStatsResponse,
			append(
				options,
			)...,
		),
	)

	// Get all CAs
	r.Methods("GET").Path("/{caType}").Handler(
		httptransport.NewServer(
			e.GetCAsEndpoint,
			decodeGetCAsRequest,
			encodeGetCAsResponse,
			append(
				options,
			)...,
		),
	)

	// Get CA by Name
	r.Methods("GET").Path("/{caType}/{caName}").Handler(
		httptransport.NewServer(
			e.GetCAByNameEndpoint,
			decodeGetCAByNameRequest,
			encodeGetCAByNameResponse,
			append(
				options,
			)...,
		),
	)

	// Create new CA using Form
	r.Methods("POST").Path("/pki").Handler(
		httptransport.NewServer(
			e.CreateCAEndpoint,
			decodeCreateCARequest,
			encodeCreateCAResponse,
			append(
				options,
			)...,
		),
	)

	// Import existing crt and key
	// r.Methods("POST").Path("/pki/import/{caName}").Handler(httptransport.NewServer(
	// 	e.ImportCAEndpoint,
	// 	decodeImportCARequest,
	// 	encodeResponse,
	// 	append(
	// 		options,
	// 		httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "ImportCA", logger)),
	// 		httptransport.ServerBefore(HTTPToContext(logger)),
	// 	)...,
	// ))

	// Revoke CA
	r.Methods("DELETE").Path("/{caType}/{caName}").Handler(
		httptransport.NewServer(
			e.RevokeCAEndpoint,
			decodeRevokeCARequest,
			encodeRevokeCAResponse,
			append(
				options,
			)...,
		),
	)

	// Get Issued certificates by {ca}
	r.Methods("GET").Path("/{caType}/{caName}/certificates").Handler(
		httptransport.NewServer(
			e.GetCertificatesEndpoint,
			decodeGetCertificatesRequest,
			encodeGetCertificatesResponse,
			append(
				options,
			)...,
		),
	)

	// Get certificate by {ca} and {serialNumber}
	r.Methods("GET").Path("/{caType}/{caName}/certificates/{serialNumber}").Handler(
		httptransport.NewServer(
			e.GetCertEndpoint,
			decodeGetCertificateBySerialNumberRequest,
			encodeGetCertificateBySerialNumberResponse,
			append(
				options,
			)...,
		),
	)

	// Sign CSR by {ca}
	r.Methods("POST").Path("/{caType}/{caName}/sign").Handler(
		httptransport.NewServer(
			e.SignCertEndpoint,
			decodeSignCertificateRequest,
			encodeSignCertificateResponse,
			append(
				options,
			)...,
		),
	)

	// Revoke certificate issued by {ca} and {serialNumber}
	r.Methods("DELETE").Path("/{caType}/{caName}/certificates/{serialNumber}").Handler(
		httptransport.NewServer(
			e.RevokeCertEndpoint,
			decodeRevokeCertificateRequest,
			encodeRevokeCertificateResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("POST").Path("/ca/{caName}/signature/sign").Handler(
		httptransport.NewServer(
			e.SignEndpoint,
			decodeSignRequest,
			encodeSignResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("POST").Path("/ca/{caName}/signature/verify").Handler(
		httptransport.NewServer(
			e.VerifyEndpoint,
			decodeVerifyRequest,
			encodeVerifyResponse,
			append(
				options,
			)...,
		),
	)

	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	return nil, nil
}

func decodeCryptoEngineRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	return nil, nil
}

func decodeStatsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	forceRefreshString := r.URL.Query().Get("force_refresh")
	forceRefresh := false
	if forceRefreshString == "" {
		parsedForceRefresh, err := strconv.ParseBool(forceRefreshString)
		if err == nil {
			forceRefresh = parsedForceRefresh
		}
	}

	input := api.GetStatsInput{
		ForceRefesh: forceRefresh,
	}

	return input, nil
}

func decodeGetCAsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CATypeString := vars["caType"]

	return api.GetCAsInput{
		CAType:          api.ParseCAType(CATypeString),
		QueryParameters: filters.FilterQuery(r, filtrableCAModelFields()),
	}, nil
}

func decodeGetCAByNameRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CATypeString := vars["caType"]
	CAName := vars["caName"]

	return api.GetCAByNameInput{
		CAType: api.ParseCAType(CATypeString),
		CAName: CAName,
	}, nil

}

func decodeGetCertificatesRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CATypeString := vars["caType"]
	CAName := vars["caName"]

	return api.GetCertificatesInput{
		CAType:          api.ParseCAType(CATypeString),
		CAName:          CAName,
		QueryParameters: filters.FilterQuery(r, filtrableCAModelFields()),
	}, nil
}

func decodeCreateCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var input api.CreateCAInput
	var body api.CreateCAPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}
	var CAExpiration time.Time
	var IssuanceExpirationDuration time.Duration
	var IssuanceExpirationDate time.Time
	var IssuanceexpirationType api.ExpirationType

	switch api.ParseExpirationType(body.IssuanceExpirationType) {
	case api.ExpirationTypeDuration:
		IssuanceExpiration, _ := strconv.Atoi(body.IssuanceExpiration)
		IssuanceExpirationDuration = time.Duration(IssuanceExpiration)
		caExpiration, _ := strconv.Atoi(body.CAExpiration)
		CAExpiration = time.Now().Add(time.Duration(caExpiration * int(time.Second)))
		IssuanceexpirationType = api.ExpirationTypeDuration
	case api.ExpirationTypeDate:
		IssuanceExpirationDate, err = time.Parse("20060102T150405Z", body.IssuanceExpiration)
		if err != nil {
			return nil, err
		}
		CAExpiration, err = time.Parse("20060102T150405Z", body.CAExpiration)
		if err != nil {
			return nil, err
		}
		IssuanceexpirationType = api.ExpirationTypeDate
	default:
		return nil, InvalidExpirationType()
	}

	input = api.CreateCAInput{
		CAType: api.CATypePKI,
		Subject: api.Subject{
			CommonName:       body.Subject.CommonName,
			Organization:     body.Subject.Organization,
			OrganizationUnit: body.Subject.OrganizationUnit,
			Country:          body.Subject.Country,
			State:            body.Subject.State,
			Locality:         body.Subject.Locality,
		},
		KeyMetadata: api.KeyMetadata{
			KeyType: api.ParseKeyType(body.KeyMetadata.KeyType),
			KeyBits: body.KeyMetadata.KeyBits,
		},
		CAExpiration: CAExpiration,

		IssuanceExpirationDate:     &IssuanceExpirationDate,
		IssuanceExpirationDuration: &IssuanceExpirationDuration,
		IssuanceExpirationType:     IssuanceexpirationType,
	}

	return input, nil
}

// func decodeImportCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
// 	vars := mux.Vars(r)
// 	var importCaRequest endpoint.ImportCARequest
// 	err = json.NewDecoder(r.Body).Decode(&importCaRequest.CaPayload)
// 	if err != nil {
// 		return nil, InvalidJsonFormat()
// 	}
// 	caName, _ := vars["caName"]

// 	importCaRequest.CaName = caName
// 	importCaRequest.CaType = "pki"

// 	return importCaRequest, nil
// }

func decodeRevokeCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CATypeString := vars["caType"]
	CAName := vars["caName"]

	var body api.RevokeCAPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.RevokeCAInput{
		CAType:           api.ParseCAType(CATypeString),
		CAName:           CAName,
		RevocationReason: body.RevocationReason,
	}, nil
}

func decodeGetCertificateBySerialNumberRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CATypeString := vars["caType"]
	CAName := vars["caName"]
	serialNumber := vars["serialNumber"]

	return api.GetCertificateBySerialNumberInput{
		CAType:                  api.ParseCAType(CATypeString),
		CAName:                  CAName,
		CertificateSerialNumber: serialNumber,
	}, nil
}

func decodeSignCertificateRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CATypeString := vars["caType"]
	CAName := vars["caName"]

	var body api.SignCertificateRequestPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}
	var certificateExpiration time.Time
	var expirationType api.ExpirationType
	switch api.ParseExpirationType(body.ExpirationType) {
	case api.ExpirationTypeDuration:
		duration, _ := strconv.Atoi(body.CertificateExpiration)
		certificateExpiration = time.Now().Add(time.Duration(duration * int(time.Second)))
		expirationType = api.ExpirationTypeDuration
	case api.ExpirationTypeDate:
		certificateExpiration, err = time.Parse("20060102T150405Z", body.CertificateExpiration)
		if err != nil {
			return nil, err
		}
		expirationType = api.ExpirationTypeDate
	}

	decodedCert, err := base64.StdEncoding.DecodeString(body.CertificateRequest)
	// decodedCert = strings.Trim(decodedCert, "\n")
	if err != nil {
		return api.SignCertificateRequestInput{}, errors.New(lamassuErrors.ErrSignRequestNotInB64)
	}

	certBlock, _ := pem.Decode([]byte(decodedCert))
	if certBlock == nil {
		return api.SignCertificateRequestInput{}, errors.New(lamassuErrors.ErrSignRequestNotInPEMFormat)
	}
	certRequest, err := x509.ParseCertificateRequest(certBlock.Bytes)
	if err != nil {
		return api.SignCertificateRequestInput{}, errors.New("could not inflate certificate request")
	}

	return api.SignCertificateRequestInput{
		CAType:                    api.ParseCAType(CATypeString),
		CAName:                    CAName,
		CertificateSigningRequest: certRequest,
		CommonName:                body.CommonName,
		SignVerbatim:              body.SignVerbatim,
		CertificateExpiration:     certificateExpiration,
		ExpirationType:            expirationType,
	}, nil
}

func decodeRevokeCertificateRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CATypeString := vars["caType"]
	CAName := vars["caName"]
	serialNumber := vars["serialNumber"]

	var body api.RevokeCertificatePayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.RevokeCertificateInput{
		CAType:                  api.ParseCAType(CATypeString),
		CAName:                  CAName,
		CertificateSerialNumber: serialNumber,
		RevocationReason:        body.RevocationReason,
	}, nil
}

func decodeSignRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CAName := vars["caName"]

	var body api.SignRequestPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	message, err := base64.StdEncoding.DecodeString(body.Message)
	if err != nil {
		return nil, err
	}
	return api.SignInput{
		Message:          message,
		MessageType:      api.ParseMsgType(body.MessageType),
		SigningAlgorithm: api.ParseSigningAlgType(body.SigningAlgorithm),
		CaName:           CAName,
	}, nil
}

func decodeVerifyRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CAName := vars["caName"]

	var body api.VerifyRequestPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	message, err := base64.StdEncoding.DecodeString(body.Message)
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(body.Signature)
	if err != nil {
		return nil, err
	}

	return api.VerifyInput{
		Message:          message,
		MessageType:      api.ParseMsgType(body.MessageType),
		SigningAlgorithm: api.ParseSigningAlgType(body.SigningAlgorithm),
		Signature:        signature,
		CaName:           CAName,
	}, nil
}

func encodeHealthResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeCryptoEngineResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(api.EngineProviderInfo)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeStatsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.GetStatsOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeGetCAsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.GetCAsOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeGetCAByNameResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.GetCAByNameOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeCreateCAResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.CreateCAOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeRevokeCAResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.RevokeCAOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeGetCertificatesResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.GetCertificatesOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeSignCertificateResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.SignCertificateRequestOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeGetCertificateBySerialNumberResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.GetCertificateBySerialNumberOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeRevokeCertificateResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.RevokeCertificateOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeSignResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.SignOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeVerifyResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.VerifyOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeError(ctx context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		return
	}

	w.WriteHeader(codeFrom(err))
	json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()})
}

type errorWrapper struct {
	Error string `json:"error"`
}

func codeFrom(err error) int {
	switch e := err.(type) {
	case *lamassuErrors.ValidationError:
		return http.StatusBadRequest
	case *lamassuErrors.DuplicateResourceError:
		return http.StatusConflict
	case *lamassuErrors.ResourceNotFoundError:
		return http.StatusNotFound
	case *lamassuErrors.GenericError:
		return e.StatusCode
	default:
		switch e.Error() {
		case lamassuErrors.ErrAlreadyRevoked:
			return http.StatusConflict
		case lamassuErrors.ErrSignRequestNotInPEMFormat:
			return http.StatusBadRequest
		case lamassuErrors.ErrSignRequestNotInB64:
			return http.StatusBadRequest
		default:
			return http.StatusInternalServerError
		}
	}
}
