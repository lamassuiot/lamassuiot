package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// The VA tells a deleted CA from an unreachable CA service by this error.
func TestCASDKGetCAByIDMapsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"err": errs.ErrCANotFound.Error()}) // what the CA controller answers
	}))
	defer server.Close()

	_, err := NewHttpCAClient(server.Client(), server.URL).GetCAByID(context.Background(), services.GetCAByIDInput{CAID: "gone"})
	require.ErrorIs(t, err, errs.ErrCANotFound)
}
