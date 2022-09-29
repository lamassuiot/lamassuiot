package transport

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/est/server/api/endpoint"
	esterror "github.com/lamassuiot/lamassuiot/pkg/est/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
	utilstransport "github.com/lamassuiot/lamassuiot/pkg/utils/server/transport"
	stdopentracing "github.com/opentracing/opentracing-go"
	"go.mozilla.org/pkcs7"
)

type errorer interface {
	error() error
}

func ErrMissingAPS() error {
	return &esterror.GenericError{
		Message:    "APS name not specified",
		StatusCode: 404,
	}
}
func ErrNoClientCert() error {
	return &esterror.GenericError{
		Message:    "client certificate must be provided",
		StatusCode: http.StatusForbidden,
	}
}
func ErrContentType() error {
	return &esterror.GenericError{
		Message:    "The content type is not correct",
		StatusCode: 400,
	}
}
func ErrInvalidBase64() error {
	return &esterror.GenericError{
		Message:    "invalid base64 encoding",
		StatusCode: http.StatusBadRequest,
	}
}
func ErrMalformedCert() error {
	return &esterror.GenericError{
		Message:    "malformed certificate",
		StatusCode: http.StatusBadRequest,
	}
}

func MakeHTTPHandler(service service.ESTService, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	router := mux.NewRouter()
	endpoints := endpoint.MakeServerEndpoints(service, otTracer)

	options := []httptransport.ServerOption{
		httptransport.ServerBefore(utilstransport.HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(EncodeError),
	}

	// MUST as per rfc7030
	router.Methods("GET").Path("/.well-known/est/cacerts").Handler(httptransport.NewServer(
		endpoints.GetCAsEndpoint,
		decodeRequest,
		encodeGetCACertificatesResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "cacerts", logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/{aps}/simpleenroll").Handler(httptransport.NewServer(
		endpoints.EnrollerEndpoint,
		decodeEnrollRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simpleenroll", logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/simplereenroll").Handler(httptransport.NewServer(
		endpoints.ReenrollerEndpoint,
		decodeReenrollRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simplereenroll", logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/{aps}/serverkeygen").Handler(httptransport.NewServer(
		endpoints.ServerKeyGenEndpoint,
		decodeServerkeygenRequest,
		encodeServerkeygenResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "serverkeygen", logger)),
		)...,
	))

	return router
}

func decodeRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.EmptyRequest
	return req, nil
}

func decodeEnrollRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	aps, ok := vars["aps"]

	if !ok {
		return nil, ErrMissingAPS()
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/pkcs10" {
		return nil, ErrContentType()
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	dec, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, ErrInvalidBase64()
	}

	csr, err := x509.ParseCertificateRequest(dec)
	if err != nil {
		return nil, ErrMalformedCert()
	}

	ClientCert := r.Header.Get("X-Forwarded-Client-Cert")

	if len(ClientCert) != 0 {
		certificate, err := getCertificateFromHeader(r.Header)
		if err != nil {
			return nil, err
		}
		return endpoint.EnrollRequest{
			Csr: csr,
			Crt: certificate,
			Aps: aps,
		}, nil

	} else if len(r.TLS.PeerCertificates) != 0 {
		cert := r.TLS.PeerCertificates[0]
		return endpoint.EnrollRequest{
			Csr: csr,
			Crt: cert,
			Aps: aps,
		}, nil

	} else {
		return nil, ErrNoClientCert()
	}
}

func decodeReenrollRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/pkcs10" {
		return nil, ErrContentType()
	}
	data, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return nil, err
	}

	dec := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(dec, data)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(dec[:n])
	if err != nil {
		return nil, ErrMalformedCert()
	}

	ClientCert := r.Header.Get("X-Forwarded-Client-Cert")
	if len(ClientCert) != 0 {
		certificate, err := getCertificateFromHeader(r.Header)
		if err != nil {
			return nil, err
		}
		return endpoint.ReenrollRequest{
			Csr: csr,
			Crt: certificate,
		}, nil
	} else if len(r.TLS.PeerCertificates) != 0 {
		cert := r.TLS.PeerCertificates[0]
		return endpoint.ReenrollRequest{
			Csr: csr,
			Crt: cert,
		}, nil

	} else {
		return nil, ErrNoClientCert()
	}

}

func decodeServerkeygenRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	aps, ok := vars["aps"]

	if !ok {
		return nil, ErrMissingAPS()
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/pkcs10" {
		return nil, ErrContentType()
	}
	data, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return nil, err
	}

	dec := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(dec, data)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(dec[:n])
	if err != nil {
		return nil, ErrMalformedCert()
	}

	clientCert := r.Header.Get("X-Forwarded-Client-Cert")
	if len(clientCert) != 0 {
		certificate, err := getCertificateFromHeader(r.Header)
		if err != nil {
			return nil, err
		}

		return endpoint.ServerKeyGenRequest{
			Csr: csr,
			Crt: certificate,
			Aps: aps,
		}, nil
	} else if len(r.TLS.PeerCertificates) != 0 {
		cert := r.TLS.PeerCertificates[0]
		return endpoint.ServerKeyGenRequest{
			Csr: csr,
			Crt: cert,
			Aps: aps,
		}, nil
	} else {
		return nil, ErrNoClientCert()
	}

}

func encodeServerkeygenResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		EncodeError(ctx, e.error(), w)
		return nil
	}
	Serverkeygenresponse := response.(endpoint.ServerKeyGenResponse)
	key := Serverkeygenresponse.Key
	cert := Serverkeygenresponse.Cert
	//cacert := Serverkeygenresponse.CaCert
	//var certs []*x509.Certificate
	//certs = append(certs, cert)
	//certs = append(certs, cacert)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	var keyContentType string

	if err != nil {
		return err
	}

	if _, p8err := x509.ParsePKCS8PrivateKey(keyDER); p8err == nil {
		keyContentType = "application/pkcs8"
	} else if _, p7err := pkcs7.Parse(keyDER); p7err == nil {
		keyContentType = "application/pkcs7-mime; smime-type=server-generated-key"
	} else {
		EncodeError(ctx, p7err, w)
		return p7err
	}

	data, contentType, err := EncodeMultiPart(
		"estServerKeyGenBoundary",
		[]MultipartPart{
			{ContentType: keyContentType, Data: keyDER},
			{ContentType: "application/pkcs7-mime; smime-type=certs-only", Data: cert},
		},
	)
	if err != nil {
		return err
	}

	//fmt.Println(data.String())

	WriteResponse(w, contentType, false, data.Bytes())
	return nil
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		EncodeError(ctx, e.error(), w)
		return nil
	}
	enrollResponse := response.(endpoint.EnrollReenrollResponse)
	cert := enrollResponse.Cert
	//cacert := enrollResponse.CaCert
	//var cb []byte
	//cb = append(cb, cert.Raw...)
	//cb = append(cb, cacert.Raw...)
	body, err := pkcs7.DegenerateCertificate(cert.Raw)
	if err != nil {
		EncodeError(ctx, err, w)
		return nil
	}
	body = []byte(base64.StdEncoding.EncodeToString(body))

	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return nil
}

func encodeGetCACertificatesResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		EncodeError(ctx, e.error(), w)
		return nil
	}
	getCAsResponse := response.(endpoint.GetCasResponse)
	var cb []byte
	for _, cert := range getCAsResponse.Certs {
		cb = append(cb, cert.Raw...)
	}

	body, err := pkcs7.DegenerateCertificate(cb)
	if err != nil {
		EncodeError(ctx, err, w)
		return nil
	}

	body = []byte(base64.StdEncoding.EncodeToString(body))

	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")

	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return nil
}

func EncodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	http.Error(w, err.Error(), codeFrom(err))
}

func codeFrom(err error) int {
	switch e := err.(type) {
	case *esterror.ValidationError:
		return http.StatusBadRequest
	case *esterror.UnAuthorized:
		return http.StatusUnauthorized
	case *esterror.GenericError:
		return e.StatusCode
	default:
		return http.StatusInternalServerError
	}
}

func getCertificateFromHeader(h http.Header) (*x509.Certificate, error) {
	forwardedClientCertificate := h.Get("X-Forwarded-Client-Cert")
	if len(forwardedClientCertificate) != 0 {
		splits := strings.Split(forwardedClientCertificate, ";")
		for _, split := range splits {
			splitedKeyVal := strings.Split(split, "=")
			if len(splitedKeyVal) == 2 {
				key := splitedKeyVal[0]
				val := splitedKeyVal[1]
				if key == "Cert" {
					cert := strings.Replace(val, "\"", "", -1)
					decodedCert, _ := url.QueryUnescape(cert)
					block, _ := pem.Decode([]byte(decodedCert))
					certificate, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						return nil, ErrMalformedCert()
					}

					return certificate, nil
				}
			}
		}
	}
	return nil, ErrNoClientCert()
}
