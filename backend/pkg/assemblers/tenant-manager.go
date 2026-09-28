package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func AssembleTenantManagerServiceWithHTTPServer(conf config.TenantManagerConfig, serviceInfo models.APIServiceInfo, routeOptions ...routes.TenantRouteOptions) (*services.TenantManagerService, int, error) {
	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "Tenant Manager", "HTTP Server")
	svc, err := AssembleTenantManagerService(conf)
	if err != nil {
		return nil, -1, err
	}
	tenantOptions, err := resolveTenantRouteOptions(lHttp, conf.Storage, conf.Server, routeOptions)
	if err != nil {
		return nil, -1, fmt.Errorf("could not configure tenant-aware HTTP routes: %w", err)
	}

	httpEngine := routes.NewGinEngineWithCORS(lHttp, conf.Server.CORSAllowedOrigins, tenantOptions.JWTValidator)
	routes.NewTenantManagerHTTPLayer(lHttp, httpEngine.Group("/"), svc, tenantOptions)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run tenant manager http server: %w", err)
	}
	return svc, port, nil
}

func AssembleTenantManagerService(conf config.TenantManagerConfig) (*services.TenantManagerService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "Tenant Manager", "Service")
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "Tenant Manager", "Storage")

	storageEngine, err := builder.BuildStorageEngine(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %w", err)
	}
	provider, ok := storageEngine.(storage.TenantManagementStorageProvider)
	if !ok {
		return nil, fmt.Errorf("storage engine does not support tenant management")
	}
	repo, err := provider.GetTenantManagementStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get tenant management storage: %w", err)
	}
	provisioners := make([]services.TenantManagerIdentity, 0, len(conf.Provisioners))
	for _, provisioner := range conf.Provisioners {
		provisioners = append(provisioners, services.TenantManagerIdentity{Issuer: provisioner.Issuer, Subject: provisioner.Subject})
	}
	return services.NewTenantManagerService(repo, provisioners, lSvc)
}
