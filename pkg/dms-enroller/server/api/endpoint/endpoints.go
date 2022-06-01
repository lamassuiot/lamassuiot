package endpoint

import (
	"context"
	"crypto/x509"
	"math"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	dmsenrrors "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint             endpoint.Endpoint
	PostCreateDMSEndpoint      endpoint.Endpoint
	PostCreateDMSFormEndpoint  endpoint.Endpoint
	PutChangeDMSStatusEndpoint endpoint.Endpoint
	DeleteDMSEndpoint          endpoint.Endpoint
	GetDMSsEndpoint            endpoint.Endpoint
	GetDMSbyIDEndpoint         endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var postCreateDMSEndpoint endpoint.Endpoint
	{
		postCreateDMSEndpoint = MakeCreateDMSEndpoint(s)
		postCreateDMSEndpoint = opentracing.TraceServer(otTracer, "CreateDMS")(postCreateDMSEndpoint)
	}
	var postCreateDMSFormEndpoint endpoint.Endpoint
	{
		postCreateDMSFormEndpoint = MakeCreateDMSFormEndpoint(s)
		postCreateDMSFormEndpoint = opentracing.TraceServer(otTracer, "CreateDMSForm")(postCreateDMSFormEndpoint)
	}

	var getDMSsEndpoint endpoint.Endpoint
	{
		getDMSsEndpoint = MakeGetDMSsEndpoint(s)
		getDMSsEndpoint = opentracing.TraceServer(otTracer, "GetDMSs")(getDMSsEndpoint)
	}
	var getDMSbyIDEndpoint endpoint.Endpoint
	{
		getDMSbyIDEndpoint = MakeGetDMSbyIDEndpoint(s)
		getDMSbyIDEndpoint = opentracing.TraceServer(otTracer, "GetDMSs")(getDMSbyIDEndpoint)
	}
	var putChangeDMSStatusEndpoint endpoint.Endpoint
	{
		putChangeDMSStatusEndpoint = MakeChangeDMSStatusEndpoint(s)
		putChangeDMSStatusEndpoint = opentracing.TraceServer(otTracer, "ChangeDMSStatus")(putChangeDMSStatusEndpoint)
	}
	var deleteDmsEndpoint endpoint.Endpoint
	{
		deleteDmsEndpoint = MakeDeleteDMSEndpoint(s)
		deleteDmsEndpoint = opentracing.TraceServer(otTracer, "DeleteDMS")(deleteDmsEndpoint)
	}

	return Endpoints{
		HealthEndpoint:             healthEndpoint,
		PostCreateDMSEndpoint:      postCreateDMSEndpoint,
		PostCreateDMSFormEndpoint:  postCreateDMSFormEndpoint,
		PutChangeDMSStatusEndpoint: putChangeDMSStatusEndpoint,
		DeleteDMSEndpoint:          deleteDmsEndpoint,
		GetDMSsEndpoint:            getDMSsEndpoint,
		GetDMSbyIDEndpoint:         getDMSbyIDEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeCreateDMSEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(dto.PostCSRRequest)
		err = ValidatetPostCSRRequest(req)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		dms, e := s.CreateDMS(ctx, req.Csr, req.DmsName)
		return dms, e
	}
}

func MakeCreateDMSFormEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(dto.PostDmsCreationFormRequest)
		err = ValidatePostDmsCreationFormRequest(req)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		privKey, dms, e := s.CreateDMSForm(ctx, dto.Subject(req.Subject), dto.PrivateKeyMetadata(req.KeyMetadata), req.DmsName)
		return dto.DmsCreationResponse{PrivKey: privKey, Dms: dms}, e
	}
}

func MakeGetDMSsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		_ = request.(GetDmsRequest)
		dmss, err := s.GetDMSs(ctx)
		return dmss, err
	}
}
func MakeGetDMSbyIDEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDmsIDRequest)
		dmss, err := s.GetDMSbyID(ctx, req.ID)
		return dmss, err
	}
}

func MakeChangeDMSStatusEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(dto.PutChangeDmsStatusRequest)
		err = ValidatetPutChangeDmsStatusRequest(req)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		dms, err := s.UpdateDMSStatus(ctx, req.Status, req.ID, req.CAs)
		return dms, err
	}
}

func MakeDeleteDMSEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteCSRRequest)
		err = s.DeleteDMS(ctx, req.ID)
		if err != nil {
			return "", err
		} else {
			return "OK", err
		}
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}
type GetDmsRequest struct{}

type GetDmsIDRequest struct {
	ID string
}

type GetCRTRequest struct {
	ID string
}
type PostDmsResponse struct {
	Dms dto.DMS `json:"dms,omitempty"`
	Err error   `json:"err,omitempty"`
}

type GetCRTResponse struct {
	Data *x509.Certificate
}

func ValidatetPostCSRRequest(request dto.PostCSRRequest) error {
	validate := validator.New()
	return validate.Struct(request)
}

func ValidatePostDmsCreationFormRequest(request dto.PostDmsCreationFormRequest) error {
	CreateCARequestStructLevelValidation := func(sl validator.StructLevel) {
		req := sl.Current().Interface().(dto.PostDmsCreationFormRequest)
		switch req.KeyMetadata.KeyType {
		case "RSA":
			if math.Mod(float64(req.KeyMetadata.KeyBits), 1024) != 0 || req.KeyMetadata.KeyBits < 2048 {
				sl.ReportError(req.KeyMetadata.KeyBits, "bits", "Bits", "bits1024multipleAndGt2048", "")
			}
		case "EC":
			if req.KeyMetadata.KeyBits != 224 && req.KeyMetadata.KeyBits != 256 && req.KeyMetadata.KeyBits != 384 {
				sl.ReportError(req.KeyMetadata.KeyBits, "bits", "Bits", "bitsEcdsaMultiple", "")
			}
		}
	}

	validate := validator.New()
	validate.RegisterStructValidation(CreateCARequestStructLevelValidation, dto.PostDmsCreationFormRequest{})
	return validate.Struct(request)
}

type GetPendingCSRFileResponse struct {
	Data []byte
	Err  error
}

type PostDirectCsr struct {
	CsrBase64Encoded string `json:"csr" validate:"base64"`
}

func ValidatetPutChangeDmsStatusRequest(request dto.PutChangeDmsStatusRequest) error {
	CreateCARequestStructLevelValidation := func(sl validator.StructLevel) {
		req := sl.Current().Interface().(dto.PutChangeDmsStatusRequest)
		switch req.Status {
		case "APPROVED":
			if req.CAs == nil {
				sl.ReportError(req.CAs, "CAs", "CAs", "missingCAsList", "")
			}
		}

	}

	validate := validator.New()
	validate.RegisterStructValidation(CreateCARequestStructLevelValidation, dto.PutChangeDmsStatusRequest{})
	return validate.Struct(request)
}

type PutChangeCSRsResponse struct {
	Dms dto.DMS
	Err error
}
type DeleteCSRRequest struct {
	ID string
}

type DeleteCSRResponse struct {
	Err error
}
