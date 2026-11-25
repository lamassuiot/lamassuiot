package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client of the DMS Manager, such as the AWS connector, tells a refused policy grant from a bad request by these errors.
func TestDMSManagerSDKMapsTheErrorsOfASave(t *testing.T) {
	answer := func(status int, err error) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"err": err.Error()}) // what the DMS controller answers
		}))
	}
	save := map[string]func(services.DMSManagerService) error{
		"create": func(c services.DMSManagerService) error {
			_, err := c.CreateDMS(context.Background(), services.CreateDMSInput{ID: "ra-1", Name: "RA", Settings: models.DMSSettings{}})
			return err
		},
		"update": func(c services.DMSManagerService) error {
			_, err := c.UpdateDMS(context.Background(), services.UpdateDMSInput{ID: "ra-1", Name: "RA", Settings: &models.DMSSettings{}})
			return err
		},
	}
	for name, do := range save {
		t.Run(name, func(t *testing.T) {
			forbidden := answer(http.StatusForbidden, errs.ErrDMSAuthzPolicyGrantForbidden)
			defer forbidden.Close()
			assert.ErrorIs(t, do(NewHttpDMSManagerClient(forbidden.Client(), forbidden.URL)), errs.ErrDMSAuthzPolicyGrantForbidden)

			bad := answer(http.StatusBadRequest, errs.ErrValidateBadRequest)
			defer bad.Close()
			assert.ErrorIs(t, do(NewHttpDMSManagerClient(bad.Client(), bad.URL)), errs.ErrValidateBadRequest)

			detailed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"err": errs.ErrValidateBadRequest.Error() + ": authz policy p does not exist"})
			}))
			defer detailed.Close()
			err := do(NewHttpDMSManagerClient(detailed.Client(), detailed.URL))
			require.ErrorIs(t, err, errs.ErrValidateBadRequest)
			assert.ErrorContains(t, err, "authz policy p does not exist")
		})
	}
}
