package pkg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func certificateWithCN(t *testing.T, cn string, metadata map[string]any) *models.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	crt, err := helpers.GenerateSelfSignedCertificate(key, cn)
	require.NoError(t, err)
	return &models.Certificate{
		SerialNumber: "sn-1",
		Subject:      models.Subject{CommonName: cn},
		Certificate:  (*models.X509Certificate)(crt),
		Metadata:     metadata,
	}
}

// The thing registered for a bound certificate is the device the DMS bound it to, even when the certificate
// CommonName names something else.
func TestBindDeviceIdentityRegistersTheBoundDeviceAsThing(t *testing.T) {
	cert := certificateWithCN(t, "ES", map[string]any{
		models.DMSAttachedToDeviceKey: map[string]any{"device_id": "dev-1"},
	})
	dms := &models.DMS{ID: "dms-1", Metadata: map[string]any{
		AWSIoTMetadataKey("aws-12345"): map[string]any{"registration_mode": AutomaticAWSIoTRegistrationMode},
	}}
	e := event.New()
	require.NoError(t, e.SetData(event.ApplicationJSON, models.BindIdentityToDeviceOutput{
		Certificate: cert, DMS: dms, Device: &models.Device{ID: "dev-1"},
	}))

	svc := &mockAWSCloudConnectorService{}
	svc.On("GetConnectorID").Return("aws-12345")
	svc.On("RegisterAndAttachThing", mock.Anything, mock.Anything).Return(nil)

	require.NoError(t, bindDeviceIdentityHandler(context.Background(), &e, svc, logrus.NewEntry(logrus.New())))

	svc.AssertCalled(t, "RegisterAndAttachThing", mock.Anything, mock.MatchedBy(func(in RegisterAndAttachThingInput) bool {
		return in.DeviceID == "dev-1"
	}))
}

func TestBoundDeviceID(t *testing.T) {
	cases := []struct {
		name     string
		metadata map[string]any
		want     string
	}{
		{
			name:     "BindingMetadata",
			metadata: map[string]any{models.DMSAttachedToDeviceKey: map[string]any{"device_id": "dev-1"}},
			want:     "dev-1",
		},
		{
			name:     "BindingWithoutDeviceFallsBackToCN",
			metadata: map[string]any{models.DMSAttachedToDeviceKey: map[string]any{}},
			want:     "ES",
		},
		{
			name:     "NoBindingFallsBackToCN",
			metadata: map[string]any{},
			want:     "ES",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, boundDeviceID(*certificateWithCN(t, "ES", tc.metadata)))
		})
	}
}
