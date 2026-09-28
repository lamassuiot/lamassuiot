package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

const (
	defaultExternalPostgresPort = 5432
	defaultListenAddress        = "127.0.0.1"
	defaultHTTPSPort            = 8443
	defaultHTTPPort             = 8080
)

// errSQLiteNotSupported aplica la opción (a) de la spec 009 (P1, aprobada el
// 2026-09-28): el monolito es multitenant y solo arranca con PostgreSQL.
var errSQLiteNotSupported = errors.New("-sqlite is not supported: SQLite does not isolate tenants " +
	"(no row level security, no unprivileged role and no control plane), so it cannot run the multitenant monolith. " +
	"Start with PostgreSQL instead: without storage options the monolith launches PostgreSQL in Docker, " +
	"or use an existing one with -postgres-host and -postgres-admin-password (and optionally -postgres-port and -postgres-admin-user)")

// options son las opciones de línea de órdenes del monolito, ya validadas.
type options struct {
	standardDockerPorts bool

	hsmModule string

	awsIoTManager       bool
	awsIoTManagerAKID   string
	awsIoTManagerSAK    string
	awsIoTManagerST     string
	awsIoTManagerRegion string
	awsIoTManagerID     string

	cryptoengineOptions string
	disableMonitor      bool
	disableEventbus     bool
	useAwsEventbus      bool
	useInMemoryEventbus bool
	disableUI           bool
	useSqlite           bool
	sampleData          bool

	postgresHost          string
	postgresPort          int
	postgresAdminUser     string
	postgresAdminPassword string

	devIssuer       bool
	externalIssuers []cconfig.HttpServerJWTIssuer
	issuerCAFiles   []string
	provisioners    []config.TenantManagerProvisioner

	v1DefaultTenant string
	v1SunsetRaw     string
	v1Sunset        time.Time

	listen    string
	httpsPort int
	httpPort  int
}

// parseOptions lee y valida las opciones. Un error significa que el monolito
// no debe lanzar nada.
func parseOptions(args []string, output io.Writer) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("development", flag.ContinueOnError)
	fs.SetOutput(output)

	fs.BoolVar(&o.standardDockerPorts, "standard-docker-ports", true, "use standard docker ports for services (RabbitMQ, Postgres, Vault, etc.)")

	fs.StringVar(&o.hsmModule, "hsm-module-path", "", "enable HSM support")

	fs.BoolVar(&o.awsIoTManager, "awsiot", false, "not supported in the multitenant monolith: the AWS IoT connector is not tenant-aware (the monolith exits with an error)")
	fs.StringVar(&o.awsIoTManagerAKID, "awsiot-keyid", "", "AWS IoT Manager AccessKeyID")
	fs.StringVar(&o.awsIoTManagerSAK, "awsiot-keysecret", "", "AWS IoT Manager SecretAccessKey")
	fs.StringVar(&o.awsIoTManagerST, "awsiot-sessiontoken", "", "AWS IoT Manager SessionToken")
	fs.StringVar(&o.awsIoTManagerRegion, "awsiot-region", "eu-west-1", "AWS IoT Manager Region")
	fs.StringVar(&o.awsIoTManagerID, "awsiot-id", "", "AWS IoT Manager ConnectorID")
	fs.StringVar(&o.cryptoengineOptions, "cryptoengines", "filesystem", ", separated list of crypto engines to enable ['aws-secrets','aws-kms','vault','pkcs11','filesystem']")
	fs.BoolVar(&o.disableMonitor, "disable-monitor", false, "disable crypto monitoring")
	fs.BoolVar(&o.disableEventbus, "disable-eventbus", false, "disable eventbus")
	fs.BoolVar(&o.useAwsEventbus, "use-aws-eventbus", false, "use AWS Eventbus")
	fs.BoolVar(&o.useInMemoryEventbus, "inmemory-eventbus", false, "use in-memory eventbus (no Docker required)")
	fs.BoolVar(&o.disableUI, "disable-ui", true, "the published UI (lamassu-ui) is not launched: it uses the v1 API without OIDC; -disable-ui=false is an error")
	fs.BoolVar(&o.useSqlite, "sqlite", false, "not supported: SQLite does not isolate tenants (the monolith exits with an error)")
	fs.BoolVar(&o.sampleData, "sample-data", false, "populate the server with sample data for manual testing")

	fs.StringVar(&o.postgresHost, "postgres-host", "", "use an existing PostgreSQL at this host instead of launching one in Docker (needs CREATEDB and CREATEROLE)")
	fs.IntVar(&o.postgresPort, "postgres-port", 0, fmt.Sprintf("port of the existing PostgreSQL (default %d; requires -postgres-host)", defaultExternalPostgresPort))
	fs.StringVar(&o.postgresAdminUser, "postgres-admin-user", "", "administrative user of the existing PostgreSQL (default postgres; requires -postgres-host)")
	fs.StringVar(&o.postgresAdminPassword, "postgres-admin-password", "", "password of the administrative user (requires -postgres-host)")

	fs.BoolVar(&o.devIssuer, "dev-issuer", true, "run the local token issuer on 127.0.0.1 (development only: any local process can get a token for any identity)")
	fs.Func("issuer", "external JWT issuer accepted by every service, as issuer=<iss>,jwks=<https JWKS URL> (repeatable)", func(value string) error {
		issuer, err := parseIssuerOption(value)
		if err != nil {
			return err
		}
		o.externalIssuers = append(o.externalIssuers, issuer)
		return nil
	})
	fs.Func("issuer-ca-file", "PEM CA trusted when fetching the JWKS of the -issuer providers (repeatable)", func(value string) error {
		o.issuerCAFiles = append(o.issuerCAFiles, value)
		return nil
	})

	fs.StringVar(&o.v1DefaultTenant, "v1-default-tenant", "", "serve the v1 API in this tenant (UUID); requires -v1-sunset. Without both, v1 answers 503 as with the Helm chart")
	fs.StringVar(&o.v1SunsetRaw, "v1-sunset", "", "v1 retirement date (RFC 3339) sent in the Sunset header; requires -v1-default-tenant")
	fs.Func("provisioner", "identity allowed to create organizations and tenants, as <issuer>|<subject> (repeatable; default: the local issuer's provisioner)", func(value string) error {
		provisioner, err := parseProvisionerOption(value)
		if err != nil {
			return err
		}
		o.provisioners = append(o.provisioners, provisioner)
		return nil
	})

	fs.StringVar(&o.listen, "listen", defaultListenAddress, "IP address where the proxy listens; any address other than loopback exposes the API to other hosts (services and the local token issuer stay on 127.0.0.1)")
	fs.IntVar(&o.httpsPort, "https-port", defaultHTTPSPort, "HTTPS port of the proxy (0: a random free port)")
	fs.IntVar(&o.httpPort, "http-port", defaultHTTPPort, "HTTP port of the proxy (0: a random free port)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	if err := o.validate(); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *options) validate() error {
	if o.useSqlite {
		return errSQLiteNotSupported
	}

	// P6: el conector AWS IoT llama a los SDK sin contexto de tenant.
	if o.awsIoTManager {
		return errors.New("-awsiot is not supported: the AWS IoT connector is not tenant-aware yet, " +
			"so it cannot run in the multitenant monolith (decision P6 of spec 009)")
	}
	// P4: la imagen publicada lamassu-ui usa v1 sin OIDC y no funcionaría.
	if !o.disableUI {
		return errors.New("-disable-ui=false is not supported: the published UI (lamassu-ui) uses the v1 API without OIDC, " +
			"and v1 answers 503 in the multitenant monolith (decision P4 of spec 009)")
	}
	if err := o.validateListen(); err != nil {
		return err
	}
	if err := o.validateIssuers(); err != nil {
		return err
	}
	if err := o.validateV1(); err != nil {
		return err
	}

	if o.postgresHost == "" {
		if o.postgresPort != 0 || o.postgresAdminUser != "" || o.postgresAdminPassword != "" {
			return errors.New("-postgres-port, -postgres-admin-user and -postgres-admin-password require -postgres-host")
		}
		return nil
	}
	if o.postgresAdminPassword == "" {
		return errors.New("-postgres-host requires -postgres-admin-password")
	}
	if o.postgresPort == 0 {
		o.postgresPort = defaultExternalPostgresPort
	}
	if o.postgresPort < 1 || o.postgresPort > 65535 {
		return fmt.Errorf("-postgres-port %d is not a valid TCP port", o.postgresPort)
	}
	if o.postgresAdminUser == "" {
		o.postgresAdminUser = "postgres"
	}
	return nil
}

func (o *options) validateIssuers() error {
	if !o.devIssuer && len(o.externalIssuers) == 0 {
		return errors.New("-dev-issuer=false requires at least one -issuer: the multitenant monolith cannot disable JWT authentication")
	}
	for _, file := range o.issuerCAFiles {
		pemBytes, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("-issuer-ca-file %s: %w", file, err)
		}
		if !x509.NewCertPool().AppendCertsFromPEM(pemBytes) {
			return fmt.Errorf("-issuer-ca-file %s contains no PEM certificates", file)
		}
	}
	return nil
}

// parseIssuerOption lee issuer=<iss>,jwks=<url>. El issuer se conserva
// exacto (puntos y mayúsculas, requisito 4.2); el JWKS debe ser https.
func parseIssuerOption(value string) (cconfig.HttpServerJWTIssuer, error) {
	const format = "use issuer=<iss>,jwks=<https JWKS URL>"
	fields := map[string]string{}
	for _, part := range strings.Split(value, ",") {
		key, val, ok := strings.Cut(part, "=")
		if !ok || (key != "issuer" && key != "jwks") {
			return cconfig.HttpServerJWTIssuer{}, fmt.Errorf("invalid -issuer %q: %s", value, format)
		}
		if _, dup := fields[key]; dup {
			return cconfig.HttpServerJWTIssuer{}, fmt.Errorf("invalid -issuer %q: %s appears twice", value, key)
		}
		fields[key] = val
	}
	issuer := cconfig.HttpServerJWTIssuer{Issuer: fields["issuer"], JWKSURL: fields["jwks"]}
	if issuer.Issuer == "" || issuer.JWKSURL == "" {
		return cconfig.HttpServerJWTIssuer{}, fmt.Errorf("invalid -issuer %q: %s", value, format)
	}
	jwks, err := url.Parse(issuer.JWKSURL)
	if err != nil || jwks.Scheme != "https" || jwks.Host == "" {
		return cconfig.HttpServerJWTIssuer{}, fmt.Errorf("invalid -issuer %q: the JWKS URL must be an absolute https URL", value)
	}
	return issuer, nil
}

// effectiveProvisioners son los -provisioner explícitos o, si no hay, el
// provisioner del emisor local.
func (o *options) effectiveProvisioners(local []config.TenantManagerProvisioner) []config.TenantManagerProvisioner {
	if len(o.provisioners) > 0 {
		return append([]config.TenantManagerProvisioner(nil), o.provisioners...)
	}
	return append([]config.TenantManagerProvisioner(nil), local...)
}

// parseProvisionerOption lee <iss>|<sub>; ambos se conservan exactos.
func parseProvisionerOption(value string) (config.TenantManagerProvisioner, error) {
	parts := strings.Split(value, "|")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return config.TenantManagerProvisioner{}, fmt.Errorf("invalid -provisioner %q: use <issuer>|<subject>", value)
	}
	return config.TenantManagerProvisioner{Issuer: parts[0], Subject: parts[1]}, nil
}

// v1Config es la política de v1 (P3).
func (o *options) v1Config() monoconfig.V1Config {
	return monoconfig.V1Config{DefaultTenantID: o.v1DefaultTenant, SunsetAt: o.v1Sunset}
}

// validateV1 aplica P3: sin opciones, v1 responde 503 como con el chart; con
// las dos, v1 se atiende en ese tenant hasta la fecha dada. No hay ninguna
// fecha por defecto: una sola opción es un error que nombra la que falta.
func (o *options) validateV1() error {
	switch {
	case o.v1DefaultTenant == "" && o.v1SunsetRaw == "":
		return nil
	case o.v1SunsetRaw == "":
		return errors.New("-v1-default-tenant requires -v1-sunset: v1 is served only when both are given (there is no default retirement date)")
	case o.v1DefaultTenant == "":
		return errors.New("-v1-sunset requires -v1-default-tenant: v1 is served only when both are given")
	}
	if parsed, err := uuid.Parse(o.v1DefaultTenant); err != nil || parsed.String() != strings.ToLower(o.v1DefaultTenant) {
		return fmt.Errorf("-v1-default-tenant %q must be a tenant UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)", o.v1DefaultTenant)
	}
	sunset, err := time.Parse(time.RFC3339, o.v1SunsetRaw)
	if err != nil {
		return fmt.Errorf("-v1-sunset %q must be an RFC 3339 date and time (YYYY-MM-DDThh:mm:ssZ): %w", o.v1SunsetRaw, err)
	}
	o.v1Sunset = sunset
	return nil
}

// validateListen aplica P5: el proxy escucha en una dirección IP explícita,
// 127.0.0.1 por defecto.
func (o *options) validateListen() error {
	if net.ParseIP(o.listen) == nil {
		return fmt.Errorf("-listen %q must be an IP address (default %s)", o.listen, defaultListenAddress)
	}
	for name, port := range map[string]int{"-https-port": o.httpsPort, "-http-port": o.httpPort} {
		if port < 0 || port > 65535 {
			return fmt.Errorf("%s %d is not a valid TCP port", name, port)
		}
	}
	if o.httpsPort != 0 && o.httpsPort == o.httpPort {
		return fmt.Errorf("-https-port and -http-port cannot both be %d", o.httpsPort)
	}
	return nil
}

// warnings son los avisos de las opciones que reducen la seguridad por
// defecto; se imprimen en el banner y en el log.
func (o *options) warnings() []string {
	var out []string
	if ip := net.ParseIP(o.listen); ip != nil && !ip.IsLoopback() {
		out = append(out, fmt.Sprintf("-listen %s: the proxy is reachable from other hosts, and any of them can use the API with a valid token; "+
			"the services and the local token issuer stay on 127.0.0.1", o.listen))
	}
	return out
}

// externalPostgres devuelve el PostgreSQL externo pedido con -postgres-host, o
// nil si el monolito debe lanzar uno en Docker.
func (o *options) externalPostgres() *pgconfig.PostgresPSEConfig {
	if o.postgresHost == "" {
		return nil
	}
	return &pgconfig.PostgresPSEConfig{
		Hostname: o.postgresHost,
		Port:     o.postgresPort,
		Username: o.postgresAdminUser,
		Password: cconfig.Password(o.postgresAdminPassword),
	}
}
