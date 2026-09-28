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

// internalErrorCA devuelve el mismo error en todas las operaciones de CA que
// exponen los handlers.
type internalErrorCA struct {
	services.CAService
	err error
}

func (svc internalErrorCA) GetStats(context.Context, services.GetStatsInput) (*models.CAStats, error) {
	return nil, svc.err
}

func (svc internalErrorCA) GetStatsByCAID(context.Context, services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	return nil, svc.err
}

func (svc internalErrorCA) CreateCA(context.Context, services.CreateCAInput) (*models.CACertificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) ImportCA(context.Context, services.ImportCAInput) (*models.CACertificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) GetCAByID(context.Context, services.GetCAByIDInput) (*models.CACertificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) GetCAs(context.Context, services.GetCAsInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorCA) GetCAsByCommonName(context.Context, services.GetCAsByCommonNameInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorCA) UpdateCAStatus(context.Context, services.UpdateCAStatusInput) (*models.CACertificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) UpdateCAProfile(context.Context, services.UpdateCAProfileInput) (*models.CACertificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) UpdateCAMetadata(context.Context, services.UpdateCAMetadataInput) (*models.CACertificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) ReissueCA(context.Context, services.ReissueCAInput) (*models.CACertificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) DeleteCA(context.Context, services.DeleteCAInput) error {
	return svc.err
}

func (svc internalErrorCA) SignatureSign(context.Context, services.SignatureSignInput) ([]byte, error) {
	return nil, svc.err
}

func (svc internalErrorCA) SignatureVerify(context.Context, services.SignatureVerifyInput) (bool, error) {
	return false, svc.err
}

func (svc internalErrorCA) SignCertificate(context.Context, services.SignCertificateInput) (*models.Certificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) CreateCertificate(context.Context, services.CreateCertificateInput) (*models.Certificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) ImportCertificate(context.Context, services.ImportCertificateInput) (*models.Certificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) GetCertificateBySerialNumber(context.Context, services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) GetCertificates(context.Context, services.GetCertificatesInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorCA) GetCertificatesByCA(context.Context, services.GetCertificatesByCAInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorCA) GetCertificatesByExpirationDate(context.Context, services.GetCertificatesByExpirationDateInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorCA) GetCertificatesByCaAndStatus(context.Context, services.GetCertificatesByCaAndStatusInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorCA) GetCertificatesByStatus(context.Context, services.GetCertificatesByStatusInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorCA) UpdateCertificateStatus(context.Context, services.UpdateCertificateStatusInput) (*models.Certificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) UpdateCertificateMetadata(context.Context, services.UpdateCertificateMetadataInput) (*models.Certificate, error) {
	return nil, svc.err
}

func (svc internalErrorCA) DeleteCertificate(context.Context, services.DeleteCertificateInput) error {
	return svc.err
}

func (svc internalErrorCA) GetIssuanceProfiles(context.Context, services.GetIssuanceProfilesInput) (string, error) {
	return "", svc.err
}

func (svc internalErrorCA) GetIssuanceProfileByID(context.Context, services.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	return nil, svc.err
}

func (svc internalErrorCA) CreateIssuanceProfile(context.Context, services.CreateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	return nil, svc.err
}

func (svc internalErrorCA) UpdateIssuanceProfile(context.Context, services.UpdateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	return nil, svc.err
}

func (svc internalErrorCA) DeleteIssuanceProfile(context.Context, services.DeleteIssuanceProfileInput) error {
	return svc.err
}

// TestCAInternalErrorsAreGeneric comprueba que ningún endpoint de CA devuelve
// en un 500 el texto del driver, de PostgreSQL o del engine, que el error real
// queda en el log y que los 4xx de dominio no cambian (004 T4.10).
func TestCAInternalErrorsAreGeneric(t *testing.T) {
	gin.SetMode(gin.TestMode)

	notFoundCA := map[error]int{errs.ErrCANotFound: 404, errs.ErrValidateBadRequest: 400}
	certificateUpdate := map[error]int{errs.ErrCertificateNotFound: 404, errs.ErrCertificateStatusTransitionNotAllowed: 400, errs.ErrValidateBadRequest: 400}

	endpoints := []struct {
		name        string
		method      string
		path        string
		body        string
		generic     string
		domainCodes map[error]int
	}{
		{name: "create CA", method: http.MethodPost, path: "/cas", body: `{}`, generic: "could not create CA",
			domainCodes: map[error]int{errs.ErrValidateBadRequest: 400, errs.ErrCAType: 400, errs.ErrCAIssuanceExpiration: 400, errs.ErrCAIncompatibleValidity: 400, errs.ErrIssuanceProfileNotFound: 404, errs.ErrCAAlreadyExists: 409}},
		{name: "import CA", method: http.MethodPost, path: "/cas/import", body: `{}`, generic: "could not import CA",
			domainCodes: map[error]int{errs.ErrValidateBadRequest: 400, errs.ErrCAType: 400, errs.ErrCAIssuanceExpiration: 400, errs.ErrCAIncompatibleValidity: 400, errs.ErrCAValidCertAndPrivKey: 400, errs.ErrIssuanceProfileNotFound: 404}},
		{name: "list CAs", method: http.MethodGet, path: "/cas", generic: "could not list CAs"},
		{name: "list CAs by CN", method: http.MethodGet, path: "/cas/cn/ca1", generic: "could not list CAs"},
		{name: "get CA", method: http.MethodGet, path: "/cas/ca1", generic: "could not get CA", domainCodes: notFoundCA},
		{name: "update CA metadata", method: http.MethodPut, path: "/cas/ca1/metadata", body: `{"patches":[]}`, generic: "could not update CA", domainCodes: notFoundCA},
		{name: "update CA status", method: http.MethodPost, path: "/cas/ca1/status", body: `{"status":"REVOKED"}`, generic: "could not update CA",
			domainCodes: map[error]int{errs.ErrCANotFound: 404, errs.ErrCAAlreadyRevoked: 400, errs.ErrValidateBadRequest: 400, errs.ErrCertificateStatusTransitionNotAllowed: 400}},
		{name: "update CA profile", method: http.MethodPost, path: "/cas/ca1/profile", body: `{"profile_id":"p1"}`, generic: "could not update CA",
			domainCodes: map[error]int{errs.ErrCANotFound: 404, errs.ErrIssuanceProfileNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "reissue CA", method: http.MethodPost, path: "/cas/ca1/reissue", body: `{}`, generic: "could not reissue CA",
			domainCodes: map[error]int{errs.ErrCANotFound: 404, errs.ErrCAAlreadyRevoked: 400, errs.ErrValidateBadRequest: 400, errs.ErrCAExpired: 400}},
		{name: "delete CA", method: http.MethodDelete, path: "/cas/ca1", generic: "could not delete CA",
			domainCodes: map[error]int{errs.ErrCANotFound: 404, errs.ErrValidateBadRequest: 400, errs.ErrCAStatus: 400, errs.ErrCascadeDeleteNotAllowed: 403}},
		{name: "list certificates by CA", method: http.MethodGet, path: "/cas/ca1/certificates", generic: "could not list certificates",
			domainCodes: map[error]int{errs.ErrValidateBadRequest: 400, errs.ErrCANotFound: 404}},
		{name: "list certificates by CA and status", method: http.MethodGet, path: "/cas/ca1/certificates/status/ACTIVE", generic: "could not list certificates",
			domainCodes: map[error]int{errs.ErrCertificateNotFound: 404, errs.ErrCertificateStatusTransitionNotAllowed: 400, errs.ErrValidateBadRequest: 400}},
		{name: "sign certificate", method: http.MethodPost, path: "/cas/ca1/certificates/sign", body: `{}`, generic: "could not sign certificate",
			domainCodes: map[error]int{errs.ErrCANotFound: 404, errs.ErrValidateBadRequest: 400, errs.ErrCAStatus: 400}},
		{name: "signature sign", method: http.MethodPost, path: "/cas/ca1/signature/sign", body: `{"message":"aGk="}`, generic: "could not sign message",
			domainCodes: map[error]int{errs.ErrCANotFound: 404}},
		{name: "signature verify", method: http.MethodPost, path: "/cas/ca1/signature/verify", body: `{"message":"aGk=","signature":"aGk="}`, generic: "could not verify signature",
			domainCodes: map[error]int{errs.ErrCANotFound: 404}},
		{name: "get CA certificate", method: http.MethodGet, path: "/cas/ca1/certificates/sn1", generic: "could not get certificate",
			domainCodes: map[error]int{errs.ErrCertificateNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "list certificates", method: http.MethodGet, path: "/certificates", generic: "could not list certificates"},
		{name: "list certificates by status", method: http.MethodGet, path: "/certificates/status/ACTIVE", generic: "could not list certificates",
			domainCodes: map[error]int{errs.ErrValidateBadRequest: 400}},
		{name: "list certificates by expiration", method: http.MethodGet, path: "/certificates/expiration", generic: "could not list certificates"},
		{name: "get certificate", method: http.MethodGet, path: "/certificates/sn1", generic: "could not get certificate",
			domainCodes: map[error]int{errs.ErrCertificateNotFound: 404, errs.ErrValidateBadRequest: 400}},
		{name: "update certificate status", method: http.MethodPut, path: "/certificates/sn1/status", body: `{"status":"REVOKED"}`, generic: "could not update certificate", domainCodes: certificateUpdate},
		{name: "update certificate metadata", method: http.MethodPut, path: "/certificates/sn1/metadata", body: `{"patches":[]}`, generic: "could not update certificate", domainCodes: certificateUpdate},
		{name: "delete certificate", method: http.MethodDelete, path: "/certificates/sn1", generic: "could not delete certificate",
			domainCodes: map[error]int{errs.ErrCertificateNotFound: 404, errs.ErrCertificateIssuerCAExists: 400, errs.ErrValidateBadRequest: 400}},
		{name: "import certificate", method: http.MethodPost, path: "/certificates/import", body: `{}`, generic: "could not import certificate"},
		{name: "create certificate", method: http.MethodPost, path: "/certificates", body: `{}`, generic: "could not create certificate",
			domainCodes: map[error]int{errs.ErrInvalidKeySpec: 400, errs.ErrValidateBadRequest: 400, errs.ErrCAStatus: 400, errs.ErrCANotFound: 404, errs.ErrKeyNotFound: 404, errs.ErrIssuanceProfileNotFound: 404}},
		{name: "stats", method: http.MethodGet, path: "/stats", generic: "could not get stats",
			domainCodes: map[error]int{errs.ErrValidateBadRequest: 400}},
		{name: "stats by CA", method: http.MethodGet, path: "/stats/ca1", generic: "could not get stats",
			domainCodes: map[error]int{errs.ErrValidateBadRequest: 400}},
		{name: "list issuance profiles", method: http.MethodGet, path: "/profiles", generic: "could not list issuance profiles"},
		{name: "get issuance profile", method: http.MethodGet, path: "/profiles/p1", generic: "could not get issuance profile"},
		{name: "create issuance profile", method: http.MethodPost, path: "/profiles", body: `{}`, generic: "could not create issuance profile"},
		{name: "update issuance profile", method: http.MethodPut, path: "/profiles/p1", body: `{}`, generic: "could not update issuance profile"},
		{name: "delete issuance profile", method: http.MethodDelete, path: "/profiles/p1", generic: "could not delete issuance profile"},
	}

	internalErrors := []error{
		errors.New(`ERROR: relation "ca_certificates" does not exist (SQLSTATE 42P01)`),
		errors.New("open /crypto/tenants/tenant-b/3484baec: no such file or directory"),
	}
	leaks := []string{"SQLSTATE", "ca_certificates", "tenant-b", "no such file"}

	serve := func(routes *caHttpRoutes, method, path, body string) *httptest.ResponseRecorder {
		router := gin.New()
		router.GET("/cas", routes.GetAllCAs)
		router.POST("/cas", routes.CreateCA)
		router.POST("/cas/import", routes.ImportCA)
		router.GET("/cas/:id", routes.GetCAByID)
		router.GET("/cas/cn/:cn", routes.GetCAsByCommonName)
		router.PUT("/cas/:id/metadata", routes.UpdateCAMetadata)
		router.POST("/cas/:id/status", routes.UpdateCAStatus)
		router.POST("/cas/:id/profile", routes.UpdateCAProfile)
		router.POST("/cas/:id/reissue", routes.ReissueCA)
		router.GET("/cas/:id/certificates", routes.GetCertificatesByCA)
		router.GET("/cas/:id/certificates/status/:status", routes.GetCertificatesByCAAndStatus)
		router.POST("/cas/:id/certificates/sign", routes.SignCertificate)
		router.POST("/cas/:id/signature/sign", routes.SignatureSign)
		router.POST("/cas/:id/signature/verify", routes.SignatureVerify)
		router.GET("/cas/:id/certificates/:sn", routes.GetCertificateBySerialNumber)
		router.DELETE("/cas/:id", routes.DeleteCA)
		router.GET("/certificates", routes.GetCertificates)
		router.GET("/certificates/status/:status", routes.GetCertificatesByStatus)
		router.GET("/certificates/expiration", routes.GetCertificatesByExpirationDate)
		router.GET("/certificates/:sn", routes.GetCertificateBySerialNumber)
		router.PUT("/certificates/:sn/status", routes.UpdateCertificateStatus)
		router.PUT("/certificates/:sn/metadata", routes.UpdateCertificateMetadata)
		router.DELETE("/certificates/:sn", routes.DeleteCertificate)
		router.POST("/certificates/import", routes.ImportCertificate)
		router.POST("/certificates", routes.CreateCertificate)
		router.GET("/stats", routes.GetStats)
		router.GET("/stats/:id", routes.GetStatsByCAID)
		router.GET("/profiles", routes.GetIssuanceProfiles)
		router.GET("/profiles/:id", routes.GetIssuanceProfileByID)
		router.POST("/profiles", routes.CreateIssuanceProfile)
		router.PUT("/profiles/:id", routes.UpdateIssuanceProfile)
		router.DELETE("/profiles/:id", routes.DeleteIssuanceProfile)

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
				routes := NewCAHttpRoutes(logrus.NewEntry(logger), internalErrorCA{err: internalErr})
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
				routes := NewCAHttpRoutes(logrus.NewEntry(logrus.New()), internalErrorCA{err: domainErr})
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
