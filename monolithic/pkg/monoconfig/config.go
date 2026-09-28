// Package monoconfig contiene la configuración del monolito de desarrollo. Vive
// fuera de pkg para que pkg/devprofile la use sin crear un ciclo con el
// ensamblador (pkg importa devprofile).
package monoconfig

import (
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
)

type LamassuMonolithicAssembleMode string

const (
	//all Lamassu service but the proxy server are deployed in memory. If services interact between them,
	//they do so by using each other's Business Logic (aka Service).
	InMemory LamassuMonolithicAssembleMode = "IN_MEMORY"
	//each Lamassu service is deployed as separate HTTP servers. If services interact between them, HTTP clients (SDKs) are used
	Http LamassuMonolithicAssembleMode = "HTTP"
)

type MonolithicConfig struct {
	OtelConfig            cconfig.OTELConfig             `mapstructure:"otel"`
	Logs                  cconfig.Logging                `mapstructure:"logs"`
	PublisherEventBus     cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	SubscriberEventBus    cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	SubscriberDLQEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_dlq_event_bus"`
	Storage               cconfig.PluggableStorageEngine `mapstructure:"storage"`
	CryptoEngines         []cconfig.CryptoEngineConfig   `mapstructure:"crypto_engines"`
	Monitoring            cconfig.MonitoringJob          `mapstructure:"monitoring"`
	Domains               []string                       `mapstructure:"domains"`
	AssemblyMode          LamassuMonolithicAssembleMode  `mapstructure:"assembly_mode"`
	GatewayPortHttps      int                            `mapstructure:"gateway_port_https"`
	GatewayPortHttp       int                            `mapstructure:"gateway_port_http"`
	AWSIoTManager         MonolithicAWSIoTManagerConfig  `mapstructure:"aws_iot_manager"`
	VAStorageDir          string                         `mapstructure:"va_storage_directory"`
	UIPort                int                            `mapstructure:"ui_port"`
	PopulateSampleData    bool                           `mapstructure:"populate_sample_data"`
	Multitenant           MultitenantConfig              `mapstructure:"multitenant"`
}

type MonolithicAWSIoTManagerConfig struct {
	Enabled      bool              `mapstructure:"enabled"`
	ConnectorID  string            `mapstructure:"connector_id"`
	AWSSDKConfig laws.AWSSDKConfig `mapstructure:"aws_config"`
}

// Service identifica un servicio del monolito.
type Service string

const (
	ServiceKMS           Service = "kms"
	ServiceCA            Service = "ca"
	ServiceVA            Service = "va"
	ServiceDeviceManager Service = "devmanager"
	ServiceDMSManager    Service = "dmsmanager"
	ServiceAlerts        Service = "alerts"
	ServiceTenantManager Service = "tenants"
)

// AllServices son los siete servicios del perfil multitenant.
var AllServices = []Service{
	ServiceKMS,
	ServiceCA,
	ServiceVA,
	ServiceDeviceManager,
	ServiceDMSManager,
	ServiceAlerts,
	ServiceTenantManager,
}

// MultitenantConfig son las entradas del perfil multitenant (spec 009). No hay
// ningún campo para desactivar la autenticación JWT (requisito 4.6).
type MultitenantConfig struct {
	// ListenAddress es la interfaz de los servicios. Vacía: 127.0.0.1 (P5).
	ListenAddress string `mapstructure:"listen_address"`
	// Audience es la audiencia JWT. Vacía: devprofile.DefaultAudience.
	Audience string `mapstructure:"audience"`
	// Issuers son los issuers JWT de confianza (emisor local e IdP externos).
	Issuers []cconfig.HttpServerJWTIssuer `mapstructure:"issuers"`
	// JWKSTrustedCAFiles son las CA (PEM) en las que confían los validadores
	// JWT al descargar el JWKS, además de las del sistema: la del emisor local
	// y las de -issuer-ca-file. No se toca SSL_CERT_DIR del proceso.
	JWKSTrustedCAFiles []string `mapstructure:"jwks_trusted_ca_files"`
	// RuntimeDir es el directorio de los ficheros generados al arrancar
	// (certificados y claves). Vacío: el directorio de trabajo (hasta 009 T12).
	RuntimeDir string `mapstructure:"runtime_dir"`
	// Provisioners son las identidades que pueden crear organizaciones y tenants.
	Provisioners []config.TenantManagerProvisioner `mapstructure:"provisioners"`
	V1           V1Config                          `mapstructure:"v1"`
	InternalTLS  InternalTLSConfig                 `mapstructure:"internal_tls"`
}

// V1Config activa v1 solo si se dan los dos valores (P3); ninguno: v1 → 503.
type V1Config struct {
	DefaultTenantID string    `mapstructure:"default_tenant_id"`
	SunsetAt        time.Time `mapstructure:"sunset_at"`
}

// InternalTLSConfig son la CA interna, el certificado de cada servicio y el
// puerto de su listener interno (mTLS entre servicios).
type InternalTLSConfig struct {
	CAFile   string                       `mapstructure:"ca_file"`
	Services map[Service]InternalTLSFiles `mapstructure:"services"`
	Ports    map[Service]int              `mapstructure:"ports"`
}

type InternalTLSFiles struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}
