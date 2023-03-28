package controllers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/services"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
)

type estHttpRoutes struct {
	svc services.ESTService
}

var (
	ErrorMalformedCertificate     error = errors.New("malformed certificate")
	ErrorInvalidContentType       error = errors.New("invalid content type")
	ErrorMalformedBody            error = errors.New("malformed body")
	ErrorUnauthorized             error = errors.New("unauthorized")
	ErrorMissingClientCertificate error = errors.New("missing client certificate")
)

func NewESTHttpRoutes(svc services.ESTService) *estHttpRoutes {
	return &estHttpRoutes{
		svc: svc,
	}
}

type aps struct {
	APS string `uri:"aps" binding:"required"`
}

func (r *estHttpRoutes) GetCACerts(ctx *gin.Context) {
	var params aps
	ctx.ShouldBindUri(&params)

	c := ctx.Request.Context()

	cacerts, err := r.svc.CACerts(c, params.APS)
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
	}

	var cb []byte
	for _, cert := range cacerts {
		cb = append(cb, cert.Raw...)
	}

	body, err := pkcs7.DegenerateCertificate(cb)
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	body = base64Encode(body)

	ctx.Writer.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	ctx.Writer.Header().Set("Content-Transfer-Encoding", "base64")

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Writer.Write(body)
}

func (r *estHttpRoutes) Enroll(ctx *gin.Context) {
	c := ctx.Request.Context()

	var params aps
	ctx.ShouldBindUri(&params)

	contentType := ctx.ContentType()
	if contentType != "application/pkcs10" {
		//TODO err in contentType
		return
	}

	data, err := ioutil.ReadAll(ctx.Request.Body)
	if err != nil {
		//TODO err in Body content
		return
	}

	dec, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		//TODO err in Body format
		return
	}

	csr, err := x509.ParseCertificateRequest(dec)
	if err != nil {
		//TODO err in Body format
		return
	}

	var authMode models.ESTAuthMode
	var crt *x509.Certificate
	//check if certificate is in X-Forwarded-Client-Cert header
	log.Debug("detecting auth mode in order: MTLS -> PSK -> JWT -> NoAuth")
	log.Debug("checking if MTLS used")

	log.Trace("checking if certificate is present in 'X-Forwarded-Client-Cert' header")
	if crt, err = getCertificateFromHeader(ctx.Request.Header); err != nil {
		if err != ErrorMissingClientCertificate {
			log.Trace("something went wrong while processing X-Forwarded-Client-Cert header: %s", err)
		}

		//no (valid) certificate in the header. check if a certificate can be obtained from client TLS connection
		if len(ctx.Request.TLS.PeerCertificates) > 0 {
			log.Trace("Using certificate presented in peer connection")
			crt = ctx.Request.TLS.PeerCertificates[0]
		} else {
			log.Trace("No certificate presented in peer connection")
		}
	}

	if crt != nil {
		authMode = models.MutualTLS
		c = context.WithValue(c, authMode, crt)
	} else {
		log.Debug("MTLS NOT used. No client certificate presented")
		log.Debug("checking if PSK used")
		log.Trace("checking if PSK is present in 'X-Psk-Key' header")
		pskHeader := ctx.Request.Header.Get("X-Psk-Key")
		if pskHeader != "" {
			authMode = models.PSK
			c = context.WithValue(c, authMode, pskHeader)
		} else {
			log.Trace("PSK NOT used. no PSK value provided")
			log.Debug("checking if JWT used")
			log.Trace("checking if JWT is present in 'Authorization' header")
			authHeader := ctx.Request.Header.Get("Authorization")
			if authHeader != "" {
				authMode = models.JWT
				authHeader = strings.ToLower(authHeader)
				if !strings.HasSuffix(authHeader, "bearer ") {
					//TODO err handle no valid bearer token
					return
				}
				jwt := strings.Replace("bearer ", authHeader, "", 1)
				c = context.WithValue(c, authMode, jwt)
			} else {
				authMode = models.NoAuth
			}
		}
	}

	signedCrt, err := r.svc.Enroll(c, authMode, csr, params.APS)
	if err != nil {
		// TODO handle error
		return
	}

	body, err := pkcs7.DegenerateCertificate(signedCrt.Raw)
	if err != nil {
		// TODO handle error
		return
	}
	body = base64Encode(body)

	ctx.Writer.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	ctx.Writer.Header().Set("Content-Transfer-Encoding", "base64")
	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Writer.Write(body)

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
						return nil, ErrorMalformedCertificate
					}

					return certificate, nil
				}
			}
		}
	}

	return nil, ErrorMissingClientCertificate
}

type MultipartPart struct {
	ContentType string
	Data        interface{}
}

const (
	base64LineLength = 76
)

// base64Encode base64-encodes a slice of bytes using standard encoding.
func base64Encode(src []byte) []byte {
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(enc, src)
	return breakLines(enc, base64LineLength)
}

// base64Decode base64-decodes a slice of bytes using standard encoding.
func base64Decode(src []byte) ([]byte, error) {
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(dec, src)
	if err != nil {
		return nil, err
	}
	return dec[:n], nil
}
func ReadAllBase64Response(r io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	decoded, err := base64Decode(b)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode HTTP response body: %w", err)
	}

	return []byte(decoded), nil
}

// encodePKCS7CertsOnly encodes a slice of certificates as a PKCS#7 degenerate
// "certs-only" response.
func encodePKCS7CertsOnly(certs []*x509.Certificate) ([]byte, error) {
	var cb []byte
	for _, cert := range certs {
		cb = append(cb, cert.Raw...)
	}
	return pkcs7.DegenerateCertificate(cb)
}

// decodePKCS7CertsOnly decodes a PKCS#7 degenerate "certs-only" response and
// returns the certificate(s) it contains.
func DecodePKCS7CertsOnly(b []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(b)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}
func ReadCertResponse(r io.Reader) ([]*x509.Certificate, error) {
	p7, err := ReadAllBase64Response(r)
	if err != nil {
		return nil, err
	}

	certs, err := DecodePKCS7CertsOnly(p7)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS7: %w", err)
	}
	return certs, nil
}

// breakLines inserts a CRLF line break in the provided slice of bytes every n
// bytes, including a terminating CRLF for the last line.
func breakLines(b []byte, n int) []byte {
	crlf := []byte{'\r', '\n'}
	initialLen := len(b)

	// Just return a terminating CRLF if the input is empty.
	if initialLen == 0 {
		return crlf
	}

	// Allocate a buffer with suitable capacity to minimize allocations.
	buf := bytes.NewBuffer(make([]byte, 0, initialLen+((initialLen/n)+1)*2))

	// Split input into CRLF-terminated lines.
	for {
		lineLen := len(b)
		if lineLen == 0 {
			break
		} else if lineLen > n {
			lineLen = n
		}

		buf.Write(b[0:lineLen])
		b = b[lineLen:]
		buf.Write(crlf)
	}

	return buf.Bytes()
}

func EncodeMultiPart(boundary string, parts []MultipartPart) (*bytes.Buffer, string, error) {
	buf := bytes.NewBuffer([]byte{})
	w := multipart.NewWriter(buf)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, "", fmt.Errorf("failed to set multipart writer boundary: %w", err)
	}

	for _, part := range parts {
		var data []byte
		var err error

		switch t := part.Data.(type) {
		case []*x509.Certificate:
			data, err = encodePKCS7CertsOnly(t)
			if err != nil {
				return nil, "", err
			}

		case *x509.Certificate:
			data, err = encodePKCS7CertsOnly([]*x509.Certificate{t})
			if err != nil {
				return nil, "", err
			}

		case *x509.CertificateRequest:
			data = t.Raw

		case []byte:
			data = t

		default:
			return nil, "", fmt.Errorf("unexpected multipart part body type: %T", t)
		}

		v := textproto.MIMEHeader{}
		v.Add("Content-Type", part.ContentType)
		v.Add("Content-Transfer-Encoding", "base64")
		data = []byte(base64.StdEncoding.EncodeToString(data))

		pw, err := w.CreatePart(v)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create multipart writer part: %w", err)
		}

		if _, err := pw.Write(data); err != nil {
			return nil, "", fmt.Errorf("failed to write to multipart writer: %w", err)
		}
	}

	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	return buf, fmt.Sprintf("%s; %s=%s", "multipart/mixed", "boundary", boundary), nil
}

func WriteResponse(w http.ResponseWriter, contentType string, encode bool, obj interface{}) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	var body []byte
	var err error

	switch t := obj.(type) {
	case []*x509.Certificate:
		body, err = encodePKCS7CertsOnly(t)

	case *x509.Certificate:
		body, err = encodePKCS7CertsOnly([]*x509.Certificate{t})

	case []byte:
		body, err = t, nil
	}

	if err != nil {
		EncodeError(context.Background(), err, w)
		return
	}

	if encode {
		w.Header().Set("Content-Transfer-Encoding", "base64")
		body = base64Encode(body)
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func EncodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
