package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
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

// skiRenamedKMS holds a key the way crypto engines before the KMS left an imported CA's key, renamed to
// the CA certificate's SKI, and ca-to-kms-migration registered it: under that SKI, not the SHA-256 key
// ID the CA records for the certificate.
type skiRenamedKMS struct {
	services.KMSService
	keys   map[string]*models.Key // by PKCS#11 URI
	signer crypto.Signer
}

func (kms *skiRenamedKMS) GetKey(_ context.Context, input services.GetKeyInput) (*models.Key, error) {
	if key, ok := kms.keys[input.Identifier]; ok {
		return key, nil
	}
	return nil, errs.ErrKeyNotFound
}

func (kms *skiRenamedKMS) GetKeysByPublicKey(context.Context, services.GetKeysByPublicKeyInput) ([]*models.Key, error) {
	return []*models.Key{}, nil
}

func (kms *skiRenamedKMS) SignMessage(_ context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	if _, ok := kms.keys[input.Identifier]; !ok {
		return nil, errs.ErrKeyNotFound
	}
	signature, err := kms.signer.Sign(rand.Reader, input.Message, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &models.MessageSignature{Signature: signature}, nil
}

func parseOpenSSLCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	cert, err := chelpers.ParseCertificate(opensslCACertPEM)
	require.NoError(t, err)
	key, err := chelpers.ParsePrivateKey([]byte(opensslCAKeyPEM))
	require.NoError(t, err)
	require.Equal(t, opensslCASKI, hex.EncodeToString(cert.SubjectKeyId), "fixture precondition")
	return cert, key.(crypto.Signer)
}

func kmsKeyFor(t *testing.T, keyID string, pub crypto.PublicKey) *models.Key {
	t.Helper()
	pemKey, err := chelpers.PublicKeyToPEM(pub)
	require.NoError(t, err)
	return &models.Key{
		KeyID: keyID, EngineID: "filesystem-1", PKCS11URI: "pkcs11:token-id=filesystem-1;id=" + keyID + ";type=private",
		Algorithm: "ECDSA", Size: 256, HasPrivateKey: true, PublicKey: base64.StdEncoding.EncodeToString([]byte(pemKey)),
	}
}

func TestCertificateSignerFindsKeysRenamedToTheirSKI(t *testing.T) {
	cert, signer := parseOpenSSLCA(t)
	// What the CA records for an imported CA: the SHA-256 key ID, which is not how the KMS names its key.
	stored := &models.Certificate{Certificate: (*models.X509Certificate)(cert), EngineID: "filesystem-1", KeyID: opensslCAKeyID}

	t.Run("the key registered under the certificate SKI signs", func(t *testing.T) {
		held := kmsKeyFor(t, opensslCASKI, cert.PublicKey)
		kms := &skiRenamedKMS{keys: map[string]*models.Key{held.PKCS11URI: held}, signer: signer}

		digest := sha256.Sum256([]byte("message signed by an imported CA"))
		signature, err := NewCertificateSigner(context.Background(), stored, kms).Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err)
		require.True(t, ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], signature))
	})

	t.Run("a different key under the certificate SKI is not used", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		held := kmsKeyFor(t, opensslCASKI, &other.PublicKey)
		kms := &skiRenamedKMS{keys: map[string]*models.Key{held.PKCS11URI: held}, signer: other}

		digest := sha256.Sum256([]byte("message"))
		_, err = NewCertificateSigner(context.Background(), stored, kms).Sign(rand.Reader, digest[:], crypto.SHA256)
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})
}
