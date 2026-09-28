package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
)

const defaultExternalPostgresPort = 5432

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
}

// parseOptions lee y valida las opciones. Un error significa que el monolito
// no debe lanzar nada.
func parseOptions(args []string, output io.Writer) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("development", flag.ContinueOnError)
	fs.SetOutput(output)

	fs.BoolVar(&o.standardDockerPorts, "standard-docker-ports", true, "use standard docker ports for services (RabbitMQ, Postgres, Vault, etc.)")

	fs.StringVar(&o.hsmModule, "hsm-module-path", "", "enable HSM support")

	fs.BoolVar(&o.awsIoTManager, "awsiot", false, "enable AWS IoT Manager")
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
	fs.BoolVar(&o.disableUI, "disable-ui", false, "Disable UI docker loading")
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

	if err := o.validateIssuers(); err != nil {
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
