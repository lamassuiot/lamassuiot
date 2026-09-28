package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/go-playground/validator/v10"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type tenantTestCryptoEngine struct {
	cryptoengines.CryptoEngine
	provider models.CryptoEngineInfo
}

func (engine tenantTestCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return engine.provider
}

type kmsTenantKeyStoreStub struct {
	storage.KMSKeysRepo
	key *models.Key
}

func (stub kmsTenantKeyStoreStub) SelectExistsByKeyID(context.Context, string) (bool, *models.Key, error) {
	return true, stub.key, nil
}

func (stub kmsTenantKeyStoreStub) SelectExistsByAlias(context.Context, string) (bool, *models.Key, error) {
	return true, stub.key, nil
}

func testKMSValidTenantContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "organization",
		TenantID:       tenantID,
		ActorID:        "actor",
		ActorType:      "user",
		CorrelationID:  "correlation",
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

func TestValidateEngineTenant(t *testing.T) {
	tests := []struct {
		name         string
		ctx          context.Context
		engineTenant string
		wantErr      bool
	}{
		{name: "global engine", ctx: context.Background(), wantErr: false},
		{name: "matching tenant", ctx: testKMSValidTenantContext("tenant-a"), engineTenant: "tenant-a", wantErr: false},
		{name: "different tenant", ctx: testKMSValidTenantContext("tenant-a"), engineTenant: "tenant-b", wantErr: true},
		{name: "missing context", ctx: context.Background(), engineTenant: "tenant-a", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEngineTenant(tt.ctx, "engine-1", tt.engineTenant)
			if tt.wantErr {
				if !errors.Is(err, core.ErrTenantResourceAccessDenied) {
					t.Fatalf("expected tenant access denied, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestKMSOperationsRequireTenantContext(t *testing.T) {
	service := &KMSServiceBackend{}
	if _, err := service.GetCryptoEngineProvider(context.Background()); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected engine listing to require tenant context, got %v", err)
	}
	if _, err := service.CreateKey(context.Background(), services.CreateKeyInput{}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected key creation to require tenant context, got %v", err)
	}
}

func TestGetCryptoEngineProviderFiltersTenantScopedEngines(t *testing.T) {
	global := tenantTestCryptoEngine{provider: models.CryptoEngineInfo{Name: "global"}}
	tenantA := tenantTestCryptoEngine{provider: models.CryptoEngineInfo{Name: "tenant-a"}}
	tenantB := tenantTestCryptoEngine{provider: models.CryptoEngineInfo{Name: "tenant-b"}}

	service := &KMSServiceBackend{
		cryptoEngines: map[string]*cryptoengines.CryptoEngine{
			"global":   cryptoEnginePointer(global),
			"engine-a": cryptoEnginePointer(tenantA),
			"engine-b": cryptoEnginePointer(tenantB),
		},
		engineTenants: map[string]string{
			"engine-a": "tenant-a",
			"engine-b": "tenant-b",
		},
	}

	providers, err := service.GetCryptoEngineProvider(testKMSValidTenantContext("tenant-a"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(providers) != 2 {
		t.Fatalf("expected global and tenant-a engines, got %d", len(providers))
	}
	for _, provider := range providers {
		if provider.ID == "engine-b" {
			t.Fatal("tenant-b engine was exposed to tenant-a")
		}
	}
}

func TestCreateKeyRejectsDifferentTenantEngine(t *testing.T) {
	kmsValidator = validator.New()
	tenantB := tenantTestCryptoEngine{provider: models.CryptoEngineInfo{Name: "tenant-b"}}
	engine := cryptoEnginePointer(tenantB)
	service := &KMSServiceBackend{
		cryptoEngines: map[string]*cryptoengines.CryptoEngine{"engine-b": engine},
		engineTenants: map[string]string{"engine-b": "tenant-b"},
		logger:        logrus.New().WithField("test", "kms-tenant"),
	}

	_, err := service.CreateKey(testKMSValidTenantContext("tenant-a"), services.CreateKeyInput{
		Algorithm: "RSA",
		Size:      2048,
		EngineID:  "engine-b",
		Name:      "cross-tenant",
	})
	if !errors.Is(err, core.ErrTenantResourceAccessDenied) {
		t.Fatalf("expected tenant access denied, got %v", err)
	}
}

func TestKMSOperationsRejectForeignTenantEngines(t *testing.T) {
	kmsValidator = validator.New()
	tenantB := tenantTestCryptoEngine{provider: models.CryptoEngineInfo{Name: "tenant-b"}}
	service := &KMSServiceBackend{
		cryptoEngines: map[string]*cryptoengines.CryptoEngine{
			"engine-b": cryptoEnginePointer(tenantB),
		},
		engineTenants: map[string]string{"engine-b": "tenant-b"},
		kmsStorage: kmsTenantKeyStoreStub{key: &models.Key{
			KeyID:    "key-b",
			EngineID: "engine-b",
			TenantID: "tenant-a",
		}},
		logger: logrus.New().WithField("test", "kms-tenant"),
	}
	ctx := testKMSValidTenantContext("tenant-a")

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "import",
			call: func() error {
				_, err := service.ImportKey(ctx, services.ImportKeyInput{
					PrivateKey: &rsa.PrivateKey{},
					EngineID:   "engine-b",
				})
				return err
			},
		},
		{
			name: "sign",
			call: func() error {
				_, err := service.SignMessage(ctx, services.SignMessageInput{
					Identifier:  "key-b",
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_256",
					Message:     []byte("message"),
					MessageType: models.Raw,
				})
				return err
			},
		},
		{
			name: "verify",
			call: func() error {
				_, err := service.VerifySignature(ctx, services.VerifySignInput{
					Identifier:  "key-b",
					Algorithm:   "RSASSA_PKCS1_V1_5_SHA_256",
					Signature:   []byte("signature"),
					Message:     []byte("message"),
					MessageType: models.Raw,
				})
				return err
			},
		},
		{
			name: "delete",
			call: func() error {
				return service.DeleteKeyByID(ctx, services.GetKeyInput{Identifier: "key-b"})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, core.ErrTenantResourceAccessDenied) {
				t.Fatalf("expected tenant access denied, got %v", err)
			}
		})
	}
}

func cryptoEnginePointer(engine cryptoengines.CryptoEngine) *cryptoengines.CryptoEngine {
	return &engine
}
