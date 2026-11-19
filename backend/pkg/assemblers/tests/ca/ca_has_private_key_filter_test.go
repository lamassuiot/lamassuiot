package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F15: the CA list endpoint must apply the has_private_key filter instead of silently dropping it.
func TestListingCAsFiltersByHasPrivateKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	svc := serverTest.CA.HttpCASDK
	profile := newKeyRefsProfile(t)

	managed, err := svc.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: "F15 managed"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
	})
	require.NoError(t, err)

	cert, _ := selfSignedCAWithForeignSKI(t, "F15 keyless")
	keyless, err := svc.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert), ProfileID: profile.ID})
	require.NoError(t, err)

	for _, tc := range []struct {
		value string
		want  string
	}{
		{"true", managed.ID},
		{"false", keyless.ID},
	} {
		filter := func() *resources.QueryParameters {
			return &resources.QueryParameters{Filters: []resources.FilterOption{
				{Field: "has_private_key", FilterOperation: resources.EnumEqual, Value: tc.value},
			}}
		}
		t.Run("GetCAs has_private_key="+tc.value, func(t *testing.T) {
			var ids []string
			_, err := svc.GetCAs(ctx, services.GetCAsInput{
				QueryParameters: filter(),
				ExhaustiveRun:   true,
				ApplyFunc:       func(ca models.CACertificate) { ids = append(ids, ca.ID) },
			})
			require.NoError(t, err)
			assert.Equal(t, []string{tc.want}, ids, fmt.Sprintf("only the CA with has_private_key=%s", tc.value))
		})
		t.Run("GetStats has_private_key="+tc.value, func(t *testing.T) {
			stats, err := svc.GetStats(ctx, services.GetStatsInput{CAQueryParameters: filter()})
			require.NoError(t, err)
			assert.Equal(t, 1, stats.CACertificatesStats.TotalCAs)
		})
	}
}
