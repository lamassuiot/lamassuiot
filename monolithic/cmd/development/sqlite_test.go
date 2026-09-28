package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ory/dockertest/v3/docker"
)

// Fragmentos que el mensaje de -sqlite debe contener (P1, opción (a)).
var sqliteMessageHints = []string{"SQLite", "does not isolate tenants", "PostgreSQL", "-postgres-host"}

func TestSQLiteOptionIsRejected(t *testing.T) {
	for _, args := range [][]string{
		{"-sqlite"},
		{"-sqlite", "-inmemory-eventbus", "-disable-ui", "-cryptoengines", "filesystem"},
		{"-sqlite", "-postgres-host", "db.local", "-postgres-admin-password", "secret"},
	} {
		_, err := parse(t, args...)
		if !errors.Is(err, errSQLiteNotSupported) {
			t.Errorf("%v: error %v, se esperaba errSQLiteNotSupported", args, err)
			continue
		}
		for _, hint := range sqliteMessageHints {
			if !strings.Contains(err.Error(), hint) {
				t.Errorf("%v: el mensaje %q no contiene %q", args, err, hint)
			}
		}
	}
}

func monolithContainerIDs(t *testing.T) map[string]bool {
	t.Helper()
	cli, err := docker.NewClientFromEnv()
	if err != nil {
		t.Fatalf("cliente Docker: %v", err)
	}
	list, err := cli.ListContainers(docker.ListContainersOptions{
		All:     true,
		Filters: map[string][]string{"label": {"group=lamassuiot-monolithic"}},
	})
	if err != nil {
		t.Fatalf("listar contenedores: %v", err)
	}
	ids := make(map[string]bool, len(list))
	for _, c := range list {
		ids[c.ID] = true
	}
	return ids
}

// Prueba de proceso: el binario con -sqlite sale con código 2, explica el
// motivo y no lanza ningún contenedor.
func TestSQLiteProcessExitsWithCode2BeforeLaunchingAnything(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "monolith")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	before := monolithContainerIDs(t)

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "-sqlite", "-inmemory-eventbus", "-disable-ui", "-cryptoengines", "filesystem")
	cmd.Dir = t.TempDir()
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("código de salida: %v, se esperaba 2\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	t.Logf("stderr: %s", strings.TrimSpace(stderr.String()))
	for _, hint := range sqliteMessageHints {
		if !strings.Contains(stderr.String(), hint) {
			t.Errorf("stderr %q no contiene %q", stderr.String(), hint)
		}
	}
	for _, launched := range []string{"LAUNCHING AUXILIARY SERVICES", "READY TO LAUNCH"} {
		if strings.Contains(stdout.String(), launched) {
			t.Errorf("el monolito llegó a %q antes de rechazar -sqlite", launched)
		}
	}

	for id := range monolithContainerIDs(t) {
		if !before[id] {
			t.Errorf("se lanzó el contenedor %s con la etiqueta group=lamassuiot-monolithic", id)
		}
	}

	if entries, _ := filepath.Glob(filepath.Join(cmd.Dir, "*")); len(entries) > 0 {
		t.Errorf("el monolito escribió ficheros en el cwd: %v", entries)
	}
}
