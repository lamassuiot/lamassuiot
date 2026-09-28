package devstorage

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	// ContainerLabel y ContainerLabelValue marcan los contenedores del monolito
	// (los limpia su cleanup).
	ContainerLabel      = "group"
	ContainerLabelValue = "lamassuiot-monolithic"

	postgresImage       = "postgres"
	postgresTag         = "14"
	postgresAdminUser   = "postgres"
	defaultPostgresPort = 5432
)

// StartOptions elige el PostgreSQL del monolito: uno externo (-postgres-host)
// o uno nuevo en Docker, en el puerto estándar o en uno aleatorio.
type StartOptions struct {
	External     *pgconfig.PostgresPSEConfig
	StandardPort bool
	// standardPortNumber sustituye a 5432 en las pruebas.
	standardPortNumber int
}

// Postgres es un PostgreSQL listo para Prepare: su usuario administrativo y
// cómo liberarlo al salir.
type Postgres struct {
	Admin pgconfig.PostgresPSEConfig
	// Launched indica que el contenedor lo lanzó el monolito (entorno desechable).
	Launched bool
	Cleanup  func()
}

// Start devuelve el PostgreSQL del monolito. No escribe ningún fichero: el
// contenedor arranca sin scripts de init y las bases las crea Prepare por SQL,
// así que el monolito no comparte el 0_init.sql de las suites de pruebas.
func Start(ctx context.Context, opts StartOptions) (*Postgres, error) {
	if opts.External != nil {
		if err := ping(*opts.External); err != nil {
			return nil, fmt.Errorf("could not connect to external PostgreSQL %s:%d as %s (-postgres-host): %w",
				opts.External.Hostname, opts.External.Port, opts.External.Username, err)
		}
		return &Postgres{Admin: *opts.External, Cleanup: func() {}}, nil
	}

	hostPort := ""
	if opts.StandardPort {
		port := opts.standardPortNumber
		if port == 0 {
			port = defaultPostgresPort
		}
		if err := checkPortFree(port); err != nil {
			return nil, fmt.Errorf("port %d is already in use, so the PostgreSQL container cannot use it: "+
				"run with -standard-docker-ports=false to use a random port, or use an existing PostgreSQL with -postgres-host: %w", port, err)
		}
		hostPort = strconv.Itoa(port)
	}

	password, err := randomPassword()
	if err != nil {
		return nil, err
	}

	cleanup, container, pool, err := dockerrunner.RunDocker(dockertest.RunOptions{
		Repository: postgresImage,
		Tag:        postgresTag,
		Env:        []string{"POSTGRES_PASSWORD=" + password},
		Labels:     map[string]string{ContainerLabel: ContainerLabelValue},
	}, func(hc *docker.HostConfig) {
		hc.PortBindings = map[docker.Port][]docker.PortBinding{
			"5432/tcp": {{HostIP: "127.0.0.1", HostPort: hostPort}},
		}
	})
	if err != nil {
		return nil, fmt.Errorf("could not launch PostgreSQL in Docker: %w", err)
	}

	port, err := strconv.Atoi(container.GetPort("5432/tcp"))
	if err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("could not read PostgreSQL container port: %w", err)
	}

	admin := pgconfig.PostgresPSEConfig{
		Hostname: "127.0.0.1",
		Port:     port,
		Username: postgresAdminUser,
		Password: config.Password(password),
	}
	if err := pool.Retry(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ping(admin)
	}); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("PostgreSQL container did not become ready: %w", err)
	}

	return &Postgres{Admin: admin, Launched: true, Cleanup: func() { _ = cleanup() }}, nil
}

func checkPortFree(port int) error {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	return l.Close()
}

func ping(cfg pgconfig.PostgresPSEConfig) error {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=5",
		cfg.Hostname, cfg.Port, cfg.Username, cfg.Password)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormLogger.Discard})
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	return sqlDB.Ping()
}
