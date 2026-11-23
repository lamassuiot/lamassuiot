package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// Every creation and import must persist a fresh UUIDv7.
func TestCreateAndImportCAAlwaysGenerateIDs(t *testing.T) {
	previous := caValidator
	caValidator = validator.New()
	t.Cleanup(func() { caValidator = previous })
	for _, importing := range []bool{false, true} {
		t.Run(fmt.Sprintf("import=%t", importing), func(t *testing.T) {
			svc, repo := newImportCAService(t)
			svc.vaServerDomains = []string{"va.example.com"}
			svc.service = &caIDProfileService{}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			svc.kmsService = &caIDKMS{importCAKMS: importCAKMS{}, key: key}
			ids := map[string]bool{}
			chain := importCAChain(t, false)
			for i := range 2 {
				var ca *models.CACertificate
				if importing {
					ca, err = svc.ImportCA(context.Background(), coreservices.ImportCAInput{CACertificate: (*models.X509Certificate)(chain[i])})
				} else {
					ca, err = svc.CreateCA(context.Background(), coreservices.CreateCAInput{
						Subject: models.Subject{CommonName: "root"}, ProfileID: "profile",
						KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
						CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
					})
				}
				require.NoError(t, err)
				require.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, ca.ID)
				require.False(t, ids[ca.ID], "each operation must generate a fresh ID")
				ids[ca.ID] = true
				require.Equal(t, ca.ID, repo.cas[ca.ID].ID)
				if !importing {
					require.Equal(t, ca.ID, ca.Certificate.IssuerCAMetadata.ID)
					require.Equal(t, []string{"http://va.example.com/crl/" + ca.ID}, ca.Certificate.Certificate.CRLDistributionPoints)
				}
			}
		})
	}
}

type caIDProfileService struct{ coreservices.CAService }

func (*caIDProfileService) GetIssuanceProfileByID(context.Context, coreservices.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	return &models.IssuanceProfile{ID: "profile"}, nil
}

type caIDKMS struct {
	importCAKMS
	key *ecdsa.PrivateKey
}

func (kms *caIDKMS) CreateKey(context.Context, coreservices.CreateKeyInput) (*models.Key, error) {
	der, err := x509.MarshalPKIXPublicKey(&kms.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &models.Key{KeyID: "01020304", Algorithm: "ECDSA", PublicKey: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}, nil
}
func (kms *caIDKMS) SignMessage(_ context.Context, input coreservices.SignMessageInput) (*models.MessageSignature, error) {
	signature, err := ecdsa.SignASN1(rand.Reader, kms.key, input.Message)
	return &models.MessageSignature{Signature: models.Signature(signature)}, err
}
