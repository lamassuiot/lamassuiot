package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// internalErrorKMS devuelve el mismo error en todas las operaciones de KMS
// que exponen los handlers distintos de crear e importar.
type internalErrorKMS struct {
	services.KMSService
	err error
}

func (svc internalErrorKMS) GetCryptoEngineProvider(context.Context) ([]*models.CryptoEngineProvider, error) {
	return nil, svc.err
}

func (svc internalErrorKMS) GetKeys(context.Context, services.GetKeysInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorKMS) GetKey(context.Context, services.GetKeyInput) (*models.Key, error) {
	return nil, svc.err
}

func (svc internalErrorKMS) GetKeyStats(context.Context, services.GetKeyStatsInput) (*models.KeyStats, error) {
	return nil, svc.err
}

func (svc internalErrorKMS) UpdateKeyAliases(context.Context, services.UpdateKeyAliasesInput) (*models.Key, error) {
	return nil, svc.err
}

func (svc internalErrorKMS) UpdateKeyMetadata(context.Context, services.UpdateKeyMetadataInput) (*models.Key, error) {
	return nil, svc.err
}

func (svc internalErrorKMS) UpdateKeyName(context.Context, services.UpdateKeyNameInput) (*models.Key, error) {
	return nil, svc.err
}

func (svc internalErrorKMS) UpdateKeyTags(context.Context, services.UpdateKeyTagsInput) (*models.Key, error) {
	return nil, svc.err
}

func (svc internalErrorKMS) DeleteKeyByID(context.Context, services.GetKeyInput) error {
	return svc.err
}

func (svc internalErrorKMS) SignMessage(context.Context, services.SignMessageInput) (*models.MessageSignature, error) {
	return nil, svc.err
}

func (svc internalErrorKMS) VerifySignature(context.Context, services.VerifySignInput) (*models.MessageValidation, error) {
	return nil, svc.err
}

func TestKMSInternalErrorsAreGeneric(t *testing.T) {
	gin.SetMode(gin.TestMode)

	endpoints := []struct {
		name        string
		method      string
		path        string
		body        string
		generic     string
		domainCodes map[error]int
	}{
		{name: "engines", method: http.MethodGet, path: "/engines", generic: "could not get crypto engines"},
		{name: "list keys", method: http.MethodGet, path: "/keys", generic: "could not list keys"},
		{name: "get key", method: http.MethodGet, path: "/keys/k1", generic: "could not get key",
			domainCodes: map[error]int{errs.ErrKeyNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "stats", method: http.MethodGet, path: "/stats", generic: "could not get key stats",
			domainCodes: map[error]int{errs.ErrValidateBadRequest: 400}},
		{name: "update aliases", method: http.MethodPut, path: "/keys/k1/alias", body: `{"patches":[]}`, generic: "could not update key",
			domainCodes: map[error]int{errs.ErrKeyNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "update metadata", method: http.MethodPut, path: "/keys/k1/metadata", body: `{"patches":[]}`, generic: "could not update key",
			domainCodes: map[error]int{errs.ErrKeyNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "update name", method: http.MethodPut, path: "/keys/k1/name", body: `{"name":"n"}`, generic: "could not update key",
			domainCodes: map[error]int{errs.ErrKeyNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "update tags", method: http.MethodPut, path: "/keys/k1/tags", body: `{"tags":["t"]}`, generic: "could not update key",
			domainCodes: map[error]int{errs.ErrKeyNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "delete", method: http.MethodDelete, path: "/keys/k1", generic: "could not delete key",
			domainCodes: map[error]int{errs.ErrKeyNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "sign", method: http.MethodPost, path: "/keys/k1/sign", body: `{"algorithm":"ECDSA_SHA_256","message":"aGk=","message_type":"raw"}`, generic: "could not sign message",
			domainCodes: map[error]int{errs.ErrKeyNotFound: 404, errs.ErrValidateBadRequest: 400, errs.ErrInvalidDigestSize: 400}},
		{name: "verify", method: http.MethodPost, path: "/keys/k1/verify", body: `{"algorithm":"ECDSA_SHA_256","message":"aGk=","signature":"aGk=","message_type":"raw"}`, generic: "could not verify signature",
			domainCodes: map[error]int{errs.ErrKeyNotFound: 404, errs.ErrValidateBadRequest: 400, errs.ErrInvalidDigestSize: 400}},
	}

	internalErrors := []error{
		errors.New(`ERROR: relation "kms_keys" does not exist (SQLSTATE 42P01)`),
		errors.New("open /crypto/tenants/tenant-b/3484baec: no such file or directory"),
	}
	leaks := []string{"SQLSTATE", "kms_keys", "tenant-b", "no such file"}

	serve := func(routes *kmsHttpRoutes, method, path, body string) *httptest.ResponseRecorder {
		router := gin.New()
		router.GET("/engines", routes.GetCryptoEngineProvider)
		router.GET("/stats", routes.GetStats)
		router.GET("/keys", routes.GetKeys)
		router.GET("/keys/:id", routes.GetKeyByID)
		router.PUT("/keys/:id/alias", routes.UpdateKeyAliases)
		router.PUT("/keys/:id/metadata", routes.UpdateKeyMetadata)
		router.PUT("/keys/:id/name", routes.UpdateKeyName)
		router.PUT("/keys/:id/tags", routes.UpdateKeyTags)
		router.DELETE("/keys/:id", routes.DeleteKeyByID)
		router.POST("/keys/:id/sign", routes.SignMessage)
		router.POST("/keys/:id/verify", routes.VerifySignature)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		return recorder
	}

	for _, endpoint := range endpoints {
		for _, internalErr := range internalErrors {
			t.Run(endpoint.name+"/internal "+internalErr.Error(), func(t *testing.T) {
				logger, hook := logtest.NewNullLogger()
				routes := NewKMSHttpRoutes(logrus.NewEntry(logger), internalErrorKMS{err: internalErr})
				recorder := serve(routes, endpoint.method, endpoint.path, endpoint.body)

				if recorder.Code != 500 {
					t.Fatalf("expected status 500, got %d body=%s", recorder.Code, recorder.Body.String())
				}
				var body map[string]string
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
					t.Fatalf("could not decode body %s: %s", recorder.Body.String(), err)
				}
				if body["err"] != endpoint.generic {
					t.Fatalf("expected error %q, got %q", endpoint.generic, body["err"])
				}
				for _, leak := range leaks {
					if strings.Contains(recorder.Body.String(), leak) {
						t.Fatalf("body leaks %q: %s", leak, recorder.Body.String())
					}
				}

				logged := false
				for _, entry := range hook.AllEntries() {
					if entry.Level == logrus.ErrorLevel && errors.Is(entryError(entry), internalErr) {
						logged = true
					}
				}
				if !logged {
					t.Fatalf("internal error was not logged at error level")
				}
			})
		}

		for domainErr, wantStatus := range endpoint.domainCodes {
			t.Run(endpoint.name+"/domain "+domainErr.Error(), func(t *testing.T) {
				routes := NewKMSHttpRoutes(logrus.NewEntry(logrus.New()), internalErrorKMS{err: domainErr})
				recorder := serve(routes, endpoint.method, endpoint.path, endpoint.body)

				if recorder.Code != wantStatus {
					t.Fatalf("expected status %d, got %d body=%s", wantStatus, recorder.Code, recorder.Body.String())
				}
				var body map[string]string
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
					t.Fatalf("could not decode body %s: %s", recorder.Body.String(), err)
				}
				if body["err"] != domainErr.Error() {
					t.Fatalf("expected error %q, got %q", domainErr.Error(), body["err"])
				}
			})
		}
	}
}

func entryError(entry *logrus.Entry) error {
	err, _ := entry.Data[logrus.ErrorKey].(error)
	return err
}
