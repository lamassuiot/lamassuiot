package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// discoveryKMS holds copies of one key pair in several engines. Only the operations
// discoverCertificateKey uses are implemented.
type discoveryKMS struct {
	services.KMSService
	copies        []*models.Key
	defaultEngine string
	enginesErr    error
}

func (kms *discoveryKMS) GetKeysByPublicKey(context.Context, services.GetKeysByPublicKeyInput) ([]*models.Key, error) {
	copies := make([]*models.Key, len(kms.copies))
	copy(copies, kms.copies)
	return copies, nil
}

func (kms *discoveryKMS) GetCryptoEngineProvider(context.Context) ([]*models.CryptoEngineProvider, error) {
	if kms.enginesErr != nil {
		return nil, kms.enginesErr
	}
	engines := []*models.CryptoEngineProvider{}
	for _, id := range []string{"a-engine", "b-engine", "c-engine"} {
		engines = append(engines, &models.CryptoEngineProvider{ID: id, Default: id == kms.defaultEngine})
	}
	return engines, nil
}

func TestDiscoverCertificateKeyEnginePreference(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	copyIn := func(engineID string, hasPrivateKey bool) *models.Key {
		return &models.Key{KeyID: "same-key", EngineID: engineID, HasPrivateKey: hasPrivateKey}
	}

	for _, tc := range []struct {
		name       string
		kms        *discoveryKMS
		preferred  string
		wantEngine string // empty: no key
	}{
		{
			name:       "default engine wins over engines sorting before it",
			kms:        &discoveryKMS{copies: []*models.Key{copyIn("a-engine", true), copyIn("c-engine", true)}, defaultEngine: "c-engine"},
			wantEngine: "c-engine",
		},
		{
			name:       "requested engine wins over the default",
			kms:        &discoveryKMS{copies: []*models.Key{copyIn("a-engine", true), copyIn("b-engine", true), copyIn("c-engine", true)}, defaultEngine: "c-engine"},
			preferred:  "b-engine",
			wantEngine: "b-engine",
		},
		{
			name:       "default engine when the requested one does not hold the key",
			kms:        &discoveryKMS{copies: []*models.Key{copyIn("a-engine", true), copyIn("c-engine", true)}, defaultEngine: "c-engine"},
			preferred:  "b-engine",
			wantEngine: "c-engine",
		},
		{
			name:       "a copy without private key is never linked",
			kms:        &discoveryKMS{copies: []*models.Key{copyIn("c-engine", false), copyIn("a-engine", true)}, defaultEngine: "c-engine"},
			wantEngine: "a-engine",
		},
		{
			name:       "only copies without private key: no key",
			kms:        &discoveryKMS{copies: []*models.Key{copyIn("c-engine", false)}, defaultEngine: "c-engine"},
			wantEngine: "",
		},
		{
			name:       "without engine list, the first engine by ID is linked",
			kms:        &discoveryKMS{copies: []*models.Key{copyIn("c-engine", true), copyIn("a-engine", true)}, enginesErr: errors.New("engines unavailable")},
			wantEngine: "a-engine",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := discoverCertificateKey(context.Background(), logrus.NewEntry(logger), tc.kms, &key.PublicKey, tc.preferred)
			if tc.wantEngine == "" {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tc.wantEngine, got.EngineID)
		})
	}
}
