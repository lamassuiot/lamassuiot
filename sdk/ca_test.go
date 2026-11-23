package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
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

// Certificate statistics have their own endpoint, guarded by the certificate read
// filter, and take the certificate filters as plain "filter" parameters.
func TestCASDKGetCertificatesStatsCallsTheCertificateStatsEndpoint(t *testing.T) {
	var gotPath string
	var gotFilters []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotFilters = r.URL.Path, r.URL.Query()["filter"]
		_ = json.NewEncoder(w).Encode(models.CertificatesStats{
			TotalCertificates: 3,
			CertificateStatus: map[models.CertificateStatus]int{models.StatusActive: 2, models.StatusRevoked: 1},
		})
	}))
	defer server.Close()

	stats, err := NewHttpCAClient(server.Client(), server.URL).GetCertificatesStats(context.Background(), services.GetCertificatesStatsInput{
		QueryParameters: &resources.QueryParameters{Filters: []resources.FilterOption{{
			Field: "subject.common_name", FilterOperation: resources.StringEqual, Value: "device-1",
		}}},
	})

	require.NoError(t, err)
	require.Equal(t, "/v1/certificates/stats", gotPath)
	require.Equal(t, []string{"subject.common_name[eq]device-1"}, gotFilters)
	require.Equal(t, 3, stats.TotalCertificates)
	require.Equal(t, 2, stats.CertificateStatus[models.StatusActive])
	require.Equal(t, 1, stats.CertificateStatus[models.StatusRevoked])
}

func TestCASDKGetCertificatesStatsMapsBadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"err": "status field cannot be filtered"})
	}))
	defer server.Close()

	stats, err := NewHttpCAClient(server.Client(), server.URL).GetCertificatesStats(context.Background(), services.GetCertificatesStatsInput{})
	require.Error(t, err)
	require.Nil(t, stats)
}

// CA statistics only carry CA filters, under "ca_filter".
func TestCASDKGetStatsSendsOnlyCAFilters(t *testing.T) {
	var gotPath string
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.Query()
		_ = json.NewEncoder(w).Encode(models.CAStats{CACertificatesStats: models.CACertificatesStats{TotalCAs: 4}})
	}))
	defer server.Close()

	stats, err := NewHttpCAClient(server.Client(), server.URL).GetStats(context.Background(), services.GetStatsInput{
		CAQueryParameters: &resources.QueryParameters{Filters: []resources.FilterOption{{
			Field: "engine_id", FilterOperation: resources.StringEqual, Value: "soft",
		}}},
	})

	require.NoError(t, err)
	require.Equal(t, "/v1/stats", gotPath)
	require.Equal(t, url.Values{"ca_filter": {"engine_id[eq]soft"}}, gotQuery)
	require.Equal(t, 4, stats.CACertificatesStats.TotalCAs)
}
