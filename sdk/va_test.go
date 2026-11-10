package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

func TestVARoleSDKUsesVersionedRoleEndpoint(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v1/roles/role", r.URL.Path)
				require.Equal(t, method, r.Method)
				if method == http.MethodPut {
					var body map[string]any
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					require.Equal(t, "certificate-serial", body["signer_certificate_serial_number"])
					require.NotContains(t, body, "subject_key_id_signer")
				}
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`{"ca_ski":"role","crl_options":{"signer_certificate_serial_number":"certificate-serial"},"latest_crl":{"version":0}}`))
				require.NoError(t, err)
			}))
			defer server.Close()
			client := NewHttpVAClient(server.Client(), server.URL)
			var role *models.VARole
			var err error
			if method == http.MethodPut {
				role, err = client.UpdateVARole(context.Background(), services.UpdateVARoleInput{CASubjectKeyID: "role", CRLRole: models.VACRLRole{SignerCertificateSerialNumber: "certificate-serial"}})
			} else {
				role, err = client.GetVARoleByID(context.Background(), services.GetVARoleInput{CASubjectKeyID: "role"})
			}
			require.NoError(t, err)
			require.Equal(t, "certificate-serial", role.CRLOptions.SignerCertificateSerialNumber)
		})
	}
}
