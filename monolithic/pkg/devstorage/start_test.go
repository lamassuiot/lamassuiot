package devstorage

import (
	"context"
	"net"
	"strings"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/ory/dockertest/v3/docker"
	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Entry {
	return chelpers.SetupLogger(cconfig.Info, "test", "devstorage")
}

func monolithContainers(t *testing.T) int {
	t.Helper()
	cli, err := docker.NewClientFromEnv()
	if err != nil {
		t.Fatalf("cliente Docker: %v", err)
	}
	list, err := cli.ListContainers(docker.ListContainersOptions{
		All:     true,
		Filters: map[string][]string{"label": {ContainerLabel + "=" + ContainerLabelValue}},
	})
	if err != nil {
		t.Fatalf("listar contenedores: %v", err)
	}
	return len(list)
}

// Un PostgreSQL lanzado aparte se usa como externo: Start no lanza Docker y
// Prepare lo deja listo.
func TestStartUsesExternalPostgresAndPrepareReadiesIt(t *testing.T) {
	external := runBarePostgres(t)
	before := monolithContainers(t)

	pg, err := Start(context.Background(), StartOptions{External: &external})
	if err != nil {
		t.Fatalf("Start con PostgreSQL externo: %v", err)
	}
	defer pg.Cleanup()

	if pg.Admin != external {
		t.Errorf("config de administrador %+v, se esperaba la externa %+v", pg.Admin, external)
	}
	if after := monolithContainers(t); after != before {
		t.Errorf("Start lanzó contenedores con PostgreSQL externo (%d → %d)", before, after)
	}

	res, err := Prepare(context.Background(), testLogger(), pg.Admin)
	if err != nil {
		t.Fatalf("Prepare sobre el PostgreSQL externo: %v", err)
	}
	if app := appConfig(t, res); app.Username != AppRole || app.Hostname != external.Hostname || app.Port != external.Port {
		t.Errorf("config de servicio %+v", app)
	}
}

func TestStartFailsClearlyWhenExternalPostgresIsUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // puerto libre: nadie escucha

	_, err = Start(context.Background(), StartOptions{External: &pgconfig.PostgresPSEConfig{Hostname: "127.0.0.1", Port: port, Username: "postgres", Password: "x"}})
	if err == nil || !strings.Contains(err.Error(), "-postgres-host") {
		t.Fatalf("error %v, se esperaba uno que nombre -postgres-host", err)
	}
}

func TestStartReportsBusyStandardPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	busy := l.Addr().(*net.TCPAddr).Port
	before := monolithContainers(t)

	_, err = Start(context.Background(), StartOptions{StandardPort: true, standardPortNumber: busy})
	if err == nil {
		t.Fatal("Start aceptó un puerto estándar ocupado")
	}
	for _, hint := range []string{"-standard-docker-ports=false", "-postgres-host"} {
		if !strings.Contains(err.Error(), hint) {
			t.Errorf("el error %q no menciona %s", err, hint)
		}
	}
	if after := monolithContainers(t); after != before {
		t.Errorf("Start lanzó un contenedor pese al puerto ocupado (%d → %d)", before, after)
	}
}

func TestStartLaunchesDockerPostgresWithoutInitScripts(t *testing.T) {
	pg, err := Start(context.Background(), StartOptions{})
	if err != nil {
		t.Fatalf("Start con Docker: %v", err)
	}
	defer pg.Cleanup()

	if _, err := Prepare(context.Background(), testLogger(), pg.Admin); err != nil {
		t.Fatalf("Prepare sobre el PostgreSQL de Docker: %v", err)
	}
}
