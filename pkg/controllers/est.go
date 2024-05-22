package controllers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
)

var lEst *logrus.Entry

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

func NewESTHttpRoutes(logger *logrus.Entry, svc services.ESTService) *estHttpRoutes {
	lEst = logger
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

	cacerts, err := r.svc.CACerts(ctx, params.APS)
	if err != nil {
		ctx.JSON(500, err)
	}

	if ctx.Request.Header.Get("accept") == "application/x-pem-file" {
		casPEM := []string{}

		for _, cert := range cacerts {
			casPEM = append(casPEM, helpers.CertificateToPEM(cert))
		}

		ctx.Writer.Header().Set("Content-Type", "application/x-pem-file")
		ctx.Writer.Write([]byte(strings.Join(casPEM, "\n")))
		return
	}

	cb := []byte{}
	for _, cert := range cacerts {
		cb = append(cb, cert.Raw...)
	}

	body, err := pkcs7.DegenerateCertificate(cb)
	if err != nil {
		ctx.JSON(500, err)
		return
	}

	body = base64Encode(body)

	ctx.Writer.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	ctx.Writer.Header().Set("Content-Transfer-Encoding", "base64")

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Writer.Write(body)
}

func (r *estHttpRoutes) EnrollReenroll(ctx *gin.Context) {
	var params aps
	err := ctx.ShouldBindUri(&params)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	csr, err := commonEnroll(ctx)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var signedCrt *x509.Certificate
	if strings.Contains(ctx.Request.URL.Path, "simplereenroll") {
		signedCrt, err = r.svc.Reenroll(ctx, csr, params.APS)
	} else {
		signedCrt, err = r.svc.Enroll(ctx, csr, params.APS)
	}
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	if ctx.Request.Header.Get("accept") == "application/x-pem-file" {
		ctx.Writer.Header().Set("Content-Type", "application/x-pem-file")
		ctx.Writer.Write([]byte(helpers.CertificateToPEM(signedCrt)))
		return
	}

	body, err := pkcs7.DegenerateCertificate(signedCrt.Raw)
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

func commonEnroll(ctx *gin.Context) (*x509.CertificateRequest, error) {
	contentType := ctx.ContentType()
	if contentType != "application/pkcs10" {
		return nil, fmt.Errorf("content-type must be application/pkcs10")
	}

	data, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read the body payload: %s", err)
	}

	dec, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("body payload must be base64 encoded")
	}

	csr, err := x509.ParseCertificateRequest(dec)
	if err != nil {
		return nil, fmt.Errorf("could not parse the payload into a csr: %s", err)
	}

	return csr, nil
}

func (r *estHttpRoutes) ServerKeyGen(ctx *gin.Context) {
	var params aps
	err := ctx.ShouldBindUri(&params)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	csr, err := commonEnroll(ctx)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	crt, key, err := r.svc.ServerKeyGen(ctx, csr, params.APS)
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	buf, contentType, err := encodeMultiPart(
		"estServerLamassuBoundary",
		[]multipartPart{
			{ContentType: "application/pkcs8", Data: keyBytes},
			{ContentType: "application/pkcs7-mime; smime-type=certs-only", Data: crt},
		},
	)
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.Writer.Header().Set("Content-Type", contentType)
	ctx.Writer.Header().Set("Content-Transfer-Encoding", "base64")

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Writer.Write(buf.Bytes())
}

type multipartPart struct {
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

func encodeMultiPart(boundary string, parts []multipartPart) (*bytes.Buffer, string, error) {
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
