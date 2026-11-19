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
	"github.com/stretchr/testify/require"
)

func TestCRLSettingsSDKUsesVersionedCRLSettingsEndpoint(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v1/crl-settings/ca-1", r.URL.Path)
				require.Equal(t, method, r.Method)
				if method == http.MethodPut {
					var body map[string]any
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					require.Equal(t, "certificate-serial", body["signer_serial_number"])
					require.NotContains(t, body, "signer_certificate_serial_number")
				}
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`{"ca_id":"ca-1","status":"ACTIVE","crl_options":{"signer_serial_number":"certificate-serial"},"latest_crl":{"version":0}}`))
				require.NoError(t, err)
			}))
			defer server.Close()
			client := NewHttpVAClient(server.Client(), server.URL)
			var settings *models.CRLSettings
			var err error
			if method == http.MethodPut {
				settings, err = client.UpdateCRLSettings(context.Background(), services.UpdateCRLSettingsInput{CAID: "ca-1", Options: models.CRLSettingsOptions{SignerSerialNumber: "certificate-serial"}})
			} else {
				settings, err = client.GetCRLSettingsByID(context.Background(), services.GetCRLSettingsInput{CAID: "ca-1"})
			}
			require.NoError(t, err)
			require.Equal(t, "certificate-serial", settings.Options.SignerSerialNumber)
			require.Equal(t, models.CRLSettingsActive, settings.Status)
		})
	}
}

func TestCRLSettingsSDKMapsStatusCodesToErrors(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusNotFound: errs.ErrCRLSettingsNotFound,
		http.StatusConflict: errs.ErrCRLSettingsNotActive,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"err": want.Error()}) // what the VA controller answers
		}))
		client := NewHttpVAClient(server.Client(), server.URL)
		_, err := client.UpdateCRLSettings(context.Background(), services.UpdateCRLSettingsInput{CAID: "ca-1", Options: models.CRLSettingsOptions{SignerSerialNumber: "sn"}})
		require.ErrorIs(t, err, want, "status %d", status)
		server.Close()
	}
}

func TestVASDKGetCRLUsesTheID(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := NewHttpVAClient(server.Client(), server.URL)

	_, _ = client.GetCRL(context.Background(), services.GetCRLResponseInput{ID: "ca id/1"})

	require.Equal(t, "/crl/ca%20id%2F1", path, "the id is escaped as one path segment")
}
