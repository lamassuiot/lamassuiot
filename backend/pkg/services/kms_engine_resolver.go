package services

import (
	"context"
	"errors"
	"sync"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

// TenantEngineDeriver construye la instancia tenant-bound de un engine global
// para el tenant indicado (004 T4.2).
type TenantEngineDeriver func(tenantID string) (cryptoengines.CryptoEngine, error)

var errCryptoEngineUnavailable = errors.New("crypto engine unavailable")

type tenantEngineKey struct {
	engineID string
	tenantID string
}

// tenantEngineSlot serializa la construcción de una instancia: las peticiones
// concurrentes del mismo (engine, tenant) esperan a una única construcción.
type tenantEngineSlot struct {
	mu     sync.Mutex
	engine cryptoengines.CryptoEngine
}

type tenantEngineCache struct {
	mu    sync.Mutex
	slots map[tenantEngineKey]*tenantEngineSlot
}

func newTenantEngineCache() *tenantEngineCache {
	return &tenantEngineCache{slots: map[tenantEngineKey]*tenantEngineSlot{}}
}

func (cache *tenantEngineCache) get(key tenantEngineKey, derive TenantEngineDeriver) (cryptoengines.CryptoEngine, error) {
	cache.mu.Lock()
	slot, ok := cache.slots[key]
	if !ok {
		slot = &tenantEngineSlot{}
		cache.slots[key] = slot
	}
	cache.mu.Unlock()

	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.engine != nil {
		return slot.engine, nil
	}
	// Un fallo no se guarda: la siguiente petición vuelve a intentarlo.
	engine, err := derive(key.tenantID)
	if err != nil {
		return nil, err
	}
	slot.engine = engine
	return engine, nil
}

// resolveEngine devuelve la instancia del engine para el tenant del contexto:
// un engine tenant-bound se devuelve tal cual si es del tenant; un engine
// global derivable se sustituye por su instancia del tenant, construida una
// sola vez; el resto de engines globales se comparten como hasta ahora.
func (svc *KMSServiceBackend) resolveEngine(ctx context.Context, engineID string) (cryptoengines.CryptoEngine, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return nil, err
	}
	engine, ok := svc.cryptoEngines[engineID]
	if !ok {
		return nil, errs.ErrCryptoEngineNotFound
	}
	if err := svc.validateEngineTenant(ctx, engineID); err != nil {
		return nil, err
	}
	derive := svc.engineDerivers[engineID]
	if derive == nil {
		return *engine, nil
	}
	if !isSafeTenantPathComponent(tenantContext.TenantID) {
		return nil, core.ErrTenantResourceAccessDenied
	}

	instance, err := svc.tenantEngines.get(tenantEngineKey{engineID: engineID, tenantID: tenantContext.TenantID}, derive)
	if err != nil {
		chelpers.ConfigureLogger(ctx, svc.logger).Errorf("could not build the tenant instance of engine %s: %s", engineID, err)
		return nil, errCryptoEngineUnavailable
	}
	return instance, nil
}

// isSafeTenantPathComponent acepta solo identificadores que pueden usarse como
// un componente de ruta (tenants/<tenant>/) sin traversal ni separadores.
func isSafeTenantPathComponent(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '-' && char != '_' {
			return false
		}
	}
	return true
}
