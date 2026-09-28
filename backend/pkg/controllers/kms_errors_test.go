package controllers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type keyWriteErrorKMS struct {
	services.KMSService
	err error
}

func (svc keyWriteErrorKMS) ImportKey(context.Context, services.ImportKeyInput) (*models.Key, error) {
	return nil, svc.err
}

func (svc keyWriteErrorKMS) CreateKey(context.Context, services.CreateKeyInput) (*models.Key, error) {
	return nil, svc.err
}

func TestKMSKeyWriteErrorsAreUniform(t *testing.T) {
	gin.SetMode(gin.TestMode)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("could not encode key: %s", err)
	}
	importBody, _ := json.Marshal(resources.ImportKeyBody{
		PrivateKey: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
	})
	createBody, _ := json.Marshal(resources.CreateKeyBody{Algorithm: "ECDSA", Size: 256})

	driverError := errors.New(`ERROR: duplicate key value violates unique constraint "keys_pkey" (SQLSTATE 23505)`)
	engineError := errors.New("openat 3484baec: file exists")

	tests := []struct {
		name       string
		path       string
		body       []byte
		err        error
		wantStatus int
		wantBody   string
	}{
		{name: "import duplicate in tenant", path: "/keys/import", body: importBody, err: errs.ErrKeyAlreadyExists, wantStatus: 409, wantBody: "key already exists"},
		{name: "import driver error", path: "/keys/import", body: importBody, err: driverError, wantStatus: 500, wantBody: "could not import key"},
		{name: "import engine error", path: "/keys/import", body: importBody, err: engineError, wantStatus: 500, wantBody: "could not import key"},
		{name: "import wrapped driver error", path: "/keys/import", body: importBody, err: fmt.Errorf("insert: %w", driverError), wantStatus: 500, wantBody: "could not import key"},
		{name: "import bad request", path: "/keys/import", body: importBody, err: errs.ErrValidateBadRequest, wantStatus: 400, wantBody: errs.ErrValidateBadRequest.Error()},
		{name: "create duplicate in tenant", path: "/keys", body: createBody, err: errs.ErrKeyAlreadyExists, wantStatus: 409, wantBody: "key already exists"},
		{name: "create driver error", path: "/keys", body: createBody, err: driverError, wantStatus: 500, wantBody: "could not create key"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			routes := NewKMSHttpRoutes(logrus.NewEntry(logrus.New()), keyWriteErrorKMS{err: test.err})
			router := gin.New()
			router.POST("/keys", routes.CreateKey)
			router.POST("/keys/import", routes.ImportKey)

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("expected status %d, got %d body=%s", test.wantStatus, recorder.Code, recorder.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("could not decode body %s: %s", recorder.Body.String(), err)
			}
			if body["err"] != test.wantBody {
				t.Fatalf("expected error %q, got %q", test.wantBody, body["err"])
			}
			for _, leak := range []string{"keys_pkey", "duplicate key", "SQLSTATE", "file exists"} {
				if strings.Contains(recorder.Body.String(), leak) {
					t.Fatalf("body leaks %q: %s", leak, recorder.Body.String())
				}
			}
		})
	}
}
