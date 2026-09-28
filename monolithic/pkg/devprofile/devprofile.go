// Package devprofile construye la configuración multitenant de cada servicio
// del monolito de desarrollo (spec 009). Es una función pura: no abre
// ficheros, puertos ni conexiones. Los valores fijos copian los del chart de
// Helm; si el chart cambia, las pruebas de este paquete fijan qué hay que
// actualizar.
package devprofile

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

const (
	// DefaultAudience es la audiencia JWT del fast-lane.
	DefaultAudience = "lamassu-api"
	// DefaultListenAddress deja los servicios en loopback (P5).
	DefaultListenAddress = "127.0.0.1"

	// Chart: auth.backendJwt.allowedAlgorithms y jwksCacheTTL.
	jwksCacheTTL = 5 * time.Minute
	// Chart: tenantRateLimit (100 req/s, ráfaga 200).
	tenantRateLimitRPS   = 100
	tenantRateLimitBurst = 200

	internalHostname = "127.0.0.1"
)

var allowedAlgorithms = []string{"RS256"}

// Profile es la configuración de los siete servicios del perfil multitenant.
type Profile struct {
	KMS           config.KMSConfig
	CA            config.CAConfig
	VA            config.VAconfig
	DeviceManager config.DeviceManagerConfig
	DMS           config.DMSconfig
	Alerts        config.AlertsConfig
	TenantManager config.TenantManagerConfig
}

// Build devuelve la configuración de cada servicio. Falla si falta algo que
// el perfil multitenant necesita: nunca devuelve una config con JWT
// desactivado ni con v1 a medio configurar.
func Build(conf monoconfig.MonolithicConfig) (*Profile, error) {
	mt := conf.Multitenant

	jwt, err := buildJWT(mt)
	if err != nil {
		return nil, err
	}

	versioning, err := buildVersioning(mt.V1)
	if err != nil {
		return nil, err
	}

	if err := validateInternalTLS(mt.InternalTLS); err != nil {
		return nil, err
	}

	listenAddress := mt.ListenAddress
	if listenAddress == "" {
		listenAddress = DefaultListenAddress
	}

	server := func(svc monoconfig.Service) cconfig.HttpServer {
		files := mt.InternalTLS.Services[svc]
		return cconfig.HttpServer{
			LogLevel:           conf.Logs.Level,
			HealthCheckLogging: true,
			ListenAddress:      listenAddress,
			Port:               0,
			Protocol:           cconfig.HTTP,
			Authentication:     cconfig.HttpServerAuthentication{JWT: jwt},
			Versioning:         versioning,
			TenantRateLimit: cconfig.HttpServerTenantRateLimit{
				Enabled:           true,
				RequestsPerSecond: tenantRateLimitRPS,
				Burst:             tenantRateLimitBurst,
			},
			InternalListener: cconfig.HttpServerInternalListener{
				Enabled:      true,
				Port:         mt.InternalTLS.Ports[svc],
				CertFile:     files.CertFile,
				KeyFile:      files.KeyFile,
				ClientCAFile: mt.InternalTLS.CAFile,
			},
		}
	}

	client := func(caller, target monoconfig.Service) cconfig.HTTPClient {
		files := mt.InternalTLS.Services[caller]
		return cconfig.HTTPClient{
			LogLevel: cconfig.Info,
			AuthMode: cconfig.MTLS,
			AuthMTLSOptions: cconfig.AuthMTLSOptions{
				CertFile: files.CertFile,
				KeyFile:  files.KeyFile,
			},
			HTTPConnection: cconfig.HTTPConnection{
				Protocol: cconfig.HTTPS,
				BasicConnection: cconfig.BasicConnection{
					Hostname:  internalHostname,
					Port:      mt.InternalTLS.Ports[target],
					TLSConfig: cconfig.TLSConfig{CACertificateFile: mt.InternalTLS.CAFile},
				},
			},
		}
	}

	logs := cconfig.Logging{Level: conf.Logs.Level}

	vaDomains := make([]string, 0, len(conf.Domains))
	for _, domain := range conf.Domains {
		vaDomains = append(vaDomains, fmt.Sprintf("%s:%d/api/va", domain, conf.GatewayPortHttp))
	}

	defaultEngine := ""
	if len(conf.CryptoEngines) > 0 {
		defaultEngine = conf.CryptoEngines[0].ID
	}

	p := &Profile{
		KMS: config.KMSConfig{
			OtelConfig: conf.OtelConfig,
			Logs:       logs,
			Server:     server(monoconfig.ServiceKMS),
			CryptoEngineConfig: config.CryptoEngines{
				LogLevel:      cconfig.Info,
				DefaultEngine: defaultEngine,
				CryptoEngines: conf.CryptoEngines,
			},
			PublisherEventBus: conf.PublisherEventBus,
			Storage:           conf.Storage,
		},
		CA: config.CAConfig{
			OtelConfig:               conf.OtelConfig,
			Logs:                     logs,
			Server:                   server(monoconfig.ServiceCA),
			PublisherEventBus:        conf.PublisherEventBus,
			Storage:                  conf.Storage,
			KMSClient:                config.KMSClient{HTTPClient: client(monoconfig.ServiceCA, monoconfig.ServiceKMS)},
			CertificateMonitoringJob: conf.Monitoring,
			VAServerDomains:          vaDomains,
		},
		VA: config.VAconfig{
			OtelConfig:            conf.OtelConfig,
			Logs:                  logs,
			Server:                server(monoconfig.ServiceVA),
			SubscriberEventBus:    conf.SubscriberEventBus,
			SubscriberDLQEventBus: conf.SubscriberDLQEventBus,
			PublisherEventBus:     conf.PublisherEventBus,
			Storage:               conf.Storage,
			FilesystemStorage: cconfig.FSStorageConfig{
				ID:   "fs",
				Type: cconfig.LocalFilesystem,
				Config: map[string]interface{}{
					"storage_directory": conf.VAStorageDir,
				},
			},
			CRLMonitoringJob: conf.Monitoring,
			CAClient:         config.CAClient{HTTPClient: client(monoconfig.ServiceVA, monoconfig.ServiceCA)},
			KMSClient:        config.KMSClient{HTTPClient: client(monoconfig.ServiceVA, monoconfig.ServiceKMS)},
			VADomains:        vaDomains,
		},
		DeviceManager: config.DeviceManagerConfig{
			OtelConfig:            conf.OtelConfig,
			Logs:                  logs,
			Server:                server(monoconfig.ServiceDeviceManager),
			PublisherEventBus:     conf.PublisherEventBus,
			SubscriberEventBus:    conf.SubscriberEventBus,
			SubscriberDLQEventBus: conf.SubscriberDLQEventBus,
			Storage:               conf.Storage,
		},
		DMS: config.DMSconfig{
			OtelConfig:        conf.OtelConfig,
			Logs:              logs,
			Server:            server(monoconfig.ServiceDMSManager),
			PublisherEventBus: conf.PublisherEventBus,
			Storage:           conf.Storage,
		},
		Alerts: config.AlertsConfig{
			OtelConfig:            conf.OtelConfig,
			Logs:                  logs,
			Server:                server(monoconfig.ServiceAlerts),
			SubscriberEventBus:    conf.SubscriberEventBus,
			SubscriberDLQEventBus: conf.SubscriberDLQEventBus,
			Storage:               conf.Storage,
		},
		TenantManager: config.TenantManagerConfig{
			Logs:         logs,
			Server:       server(monoconfig.ServiceTenantManager),
			Storage:      conf.Storage,
			Provisioners: append([]config.TenantManagerProvisioner(nil), mt.Provisioners...),
		},
	}
	p.DeviceManager.CAClient.HTTPClient = client(monoconfig.ServiceDeviceManager, monoconfig.ServiceCA)
	p.DMS.CAClient.HTTPClient = client(monoconfig.ServiceDMSManager, monoconfig.ServiceCA)
	p.DMS.DevManagerClient.HTTPClient = client(monoconfig.ServiceDMSManager, monoconfig.ServiceDeviceManager)

	return p, nil
}

// Servers devuelve la cabecera de servidor de cada servicio, por servicio.
func (p *Profile) Servers() map[monoconfig.Service]cconfig.HttpServer {
	return map[monoconfig.Service]cconfig.HttpServer{
		monoconfig.ServiceKMS:           p.KMS.Server,
		monoconfig.ServiceCA:            p.CA.Server,
		monoconfig.ServiceVA:            p.VA.Server,
		monoconfig.ServiceDeviceManager: p.DeviceManager.Server,
		monoconfig.ServiceDMSManager:    p.DMS.Server,
		monoconfig.ServiceAlerts:        p.Alerts.Server,
		monoconfig.ServiceTenantManager: p.TenantManager.Server,
	}
}

func buildJWT(mt monoconfig.MultitenantConfig) (cconfig.HttpServerJWTAuthentication, error) {
	if len(mt.Issuers) == 0 {
		return cconfig.HttpServerJWTAuthentication{}, errors.New("multitenant profile requires at least one JWT issuer")
	}

	issuers := make([]cconfig.HttpServerJWTIssuer, 0, len(mt.Issuers))
	for i, issuer := range mt.Issuers {
		if issuer.Issuer == "" {
			return cconfig.HttpServerJWTAuthentication{}, fmt.Errorf("JWT issuer %d: issuer must not be empty", i)
		}
		jwksURL, err := url.Parse(issuer.JWKSURL)
		if err != nil || jwksURL.Scheme != "https" || jwksURL.Host == "" {
			return cconfig.HttpServerJWTAuthentication{}, fmt.Errorf("JWT issuer %q: jwks_url %q must be an absolute https URL", issuer.Issuer, issuer.JWKSURL)
		}
		issuers = append(issuers, issuer)
	}

	audience := mt.Audience
	if audience == "" {
		audience = DefaultAudience
	}

	jwt := cconfig.HttpServerJWTAuthentication{
		Enabled:           true,
		Audience:          audience,
		IssuerJWKS:        issuers,
		AllowedAlgorithms: append([]string(nil), allowedAlgorithms...),
		JWKSCacheTTL:      jwksCacheTTL,
	}
	if _, _, err := jwt.ResolveIssuerJWKS(); err != nil {
		return cconfig.HttpServerJWTAuthentication{}, err
	}
	return jwt, nil
}

// buildVersioning reproduce el contrato de HttpServerVersioning: v1 solo con
// tenant y fecha de retirada; ninguno de los dos, v1 → 503 (P3).
func buildVersioning(v1 monoconfig.V1Config) (cconfig.HttpServerVersioning, error) {
	hasTenant := v1.DefaultTenantID != ""
	hasSunset := !v1.SunsetAt.IsZero()
	switch {
	case hasTenant && !hasSunset:
		return cconfig.HttpServerVersioning{}, errors.New("v1 default tenant given without v1 sunset date: set both or neither")
	case !hasTenant && hasSunset:
		return cconfig.HttpServerVersioning{}, errors.New("v1 sunset date given without v1 default tenant: set both or neither")
	case !hasTenant:
		return cconfig.HttpServerVersioning{}, nil
	}
	return cconfig.HttpServerVersioning{
		V1DefaultTenantID: v1.DefaultTenantID,
		V1SunsetAt:        v1.SunsetAt,
	}, nil
}

func validateInternalTLS(in monoconfig.InternalTLSConfig) error {
	if in.CAFile == "" {
		return errors.New("internal TLS: CA file is required")
	}
	for _, svc := range monoconfig.AllServices {
		files := in.Services[svc]
		if files.CertFile == "" || files.KeyFile == "" {
			return fmt.Errorf("internal TLS: certificate and key are required for service %s", svc)
		}
		if in.Ports[svc] < 0 {
			return fmt.Errorf("internal TLS: invalid internal port %d for service %s", in.Ports[svc], svc)
		}
	}
	return nil
}
