package main

// Pruebas de proceso de los valores por defecto (spec 009, tarea 12;
// requisitos 1.4, 10.1 y 10.3): el binario real con Docker. Cada prueba borra
// solo lo que ella crea, por ID.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func buildMonolith(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "monolith")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// monolithProcess es el binario en marcha con su salida (stdout y stderr).
type monolithProcess struct {
	cmd    *exec.Cmd
	mu     sync.Mutex
	output strings.Builder
	lines  chan string
	done   chan error
}

func startProcess(t *testing.T, bin, cwd string, args ...string) *monolithProcess {
	t.Helper()
	p := &monolithProcess{cmd: exec.Command(bin, args...), lines: make(chan string, 4096), done: make(chan error, 1)}
	p.cmd.Dir = cwd
	pr, pw := io.Pipe()
	p.cmd.Stdout, p.cmd.Stderr = pw, pw
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		for scanner.Scan() {
			p.mu.Lock()
			p.output.WriteString(scanner.Text() + "\n")
			p.mu.Unlock()
			select {
			case p.lines <- scanner.Text():
			default:
			}
		}
	}()
	go func() {
		err := p.cmd.Wait()
		_ = pw.Close()
		p.done <- err
	}()
	t.Cleanup(func() {
		if p.cmd.ProcessState == nil {
			_ = p.cmd.Process.Kill()
		}
	})
	return p
}

func (p *monolithProcess) text() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.output.String()
}

// waitReady espera la última línea del banner; falla si el proceso sale antes.
func (p *monolithProcess) waitReady(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line := <-p.lines:
			if strings.Contains(line, bannerReadyLine) {
				return
			}
		case err := <-p.done:
			p.done <- err
			t.Fatalf("el monolito salió antes de estar listo (%v):\n%s", err, p.text())
		case <-deadline:
			t.Fatalf("el monolito no estuvo listo en %s:\n%s", timeout, p.text())
		}
	}
}

func (p *monolithProcess) wait(t *testing.T, timeout time.Duration) int {
	t.Helper()
	select {
	case err := <-p.done:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
		return 0
	case <-time.After(timeout):
		t.Fatalf("el monolito no terminó en %s:\n%s", timeout, p.text())
	}
	return -1
}

func (p *monolithProcess) match(t *testing.T, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(p.text())
	if m == nil {
		t.Fatalf("la salida no contiene %q:\n%s", pattern, p.text())
	}
	return m[1]
}

func containerExists(t *testing.T, id string) bool {
	t.Helper()
	cli, err := docker.NewClientFromEnv()
	if err != nil {
		t.Fatalf("cliente Docker: %v", err)
	}
	list, err := cli.ListContainers(docker.ListContainersOptions{All: true, Filters: map[string][]string{"id": {id}}})
	if err != nil {
		t.Fatalf("listar contenedores: %v", err)
	}
	return len(list) > 0
}

// foreignContainer lanza un contenedor ajeno con la etiqueta del monolito:
// el cleanup del monolito no debe tocarlo.
func foreignContainer(t *testing.T) string {
	t.Helper()
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "14",
		Entrypoint: []string{"sleep", "600"},
		Labels:     map[string]string{"group": "lamassuiot-monolithic"},
	})
	if err != nil {
		t.Fatalf("contenedor ajeno: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })
	return resource.Container.ID
}

func nonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	return ""
}

func canDial(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// TestDefaultsProcessLoopbackPrivateRuntimeAndOwnCleanup: el binario con las
// opciones por defecto (salvo puertos aleatorios) escucha solo en loopback,
// escribe sus claves en un directorio propio 0700/0600 y nada en el cwd, y con
// Ctrl+C borra ese directorio y su PostgreSQL, pero no un contenedor ajeno con
// la misma etiqueta.
func TestDefaultsProcessLoopbackPrivateRuntimeAndOwnCleanup(t *testing.T) {
	bin := buildMonolith(t)
	foreign := foreignContainer(t)
	cwd := t.TempDir()

	p := startProcess(t, bin, cwd, "-inmemory-eventbus", "-cryptoengines", "filesystem",
		"-standard-docker-ports=false", "-https-port", "0", "-http-port", "0")
	p.waitReady(t, 5*time.Minute)
	t.Log("\n" + p.text()[strings.LastIndex(p.text(), strings.Repeat("=", 78)+"\n LAMASSU"):])

	httpsPort := p.match(t, `Proxy: https://127\.0\.0\.1:(\d+)`)
	runtimeDir := p.match(t, `Runtime directory \(0700, deleted on Ctrl\+C\): (\S+)`)
	pgContainer := p.match(t, `launched docker: Postgres \(container ([0-9a-f]{12})\)`)

	t.Run("ProxyOnlyOnLoopback", func(t *testing.T) {
		if !canDial("127.0.0.1:" + httpsPort) {
			t.Fatalf("el proxy no escucha en 127.0.0.1:%s", httpsPort)
		}
		ip := nonLoopbackIPv4(t)
		if ip == "" {
			t.Skip("sin IPv4 fuera de loopback")
		}
		if canDial(net.JoinHostPort(ip, httpsPort)) {
			t.Errorf("el proxy acepta conexiones en %s:%s", ip, httpsPort)
		}
	})

	t.Run("RuntimeFilesArePrivate", func(t *testing.T) {
		keys := 0
		err := filepath.WalkDir(runtimeDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			want := fs.FileMode(0o600)
			if d.IsDir() {
				want = 0o700
			}
			if info.Mode().Perm() != want {
				t.Errorf("%s: permisos %v, se esperaba %v", path, info.Mode().Perm(), want)
			}
			if strings.HasSuffix(path, ".key") {
				keys++
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(runtimeDir, "proxy.key")); err != nil {
			t.Errorf("proxy.key no está en el directorio propio: %v", err)
		}
		t.Logf("%d claves en %s", keys, runtimeDir)
	})

	t.Run("NothingInTheWorkingDirectory", func(t *testing.T) {
		if entries, _ := filepath.Glob(filepath.Join(cwd, "*")); len(entries) > 0 {
			t.Errorf("el monolito escribió en el cwd: %v", entries)
		}
	})

	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	code := p.wait(t, 2*time.Minute)

	t.Run("CtrlCReleasesOnlyItsOwnResources", func(t *testing.T) {
		if code != 0 {
			t.Errorf("código de salida tras Ctrl+C: %d", code)
		}
		if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
			t.Errorf("el directorio propio sigue existiendo: %v", err)
		}
		if containerExists(t, pgContainer) {
			t.Errorf("el PostgreSQL del monolito (%s) sigue existiendo", pgContainer)
		}
		if !containerExists(t, foreign) {
			t.Errorf("el cleanup borró un contenedor ajeno (%.12s)", foreign)
		}
	})
}

// TestDefaultsProcessStartupFailureExitsNonZero: requisito 1.4. PKCS#11 sin
// -hsm-module-path deja a KMS sin motor utilizable: el montaje falla, el
// proceso termina con código distinto de cero nombrando el servicio, no deja
// el proxy escuchando y borra su PostgreSQL y su directorio.
func TestDefaultsProcessStartupFailureExitsNonZero(t *testing.T) {
	bin := buildMonolith(t)
	httpsPort := freeTCPPort(t)
	p := startProcess(t, bin, t.TempDir(), "-inmemory-eventbus", "-cryptoengines", "pkcs11",
		"-standard-docker-ports=false", "-https-port", fmt.Sprint(httpsPort), "-http-port", "0")
	code := p.wait(t, 5*time.Minute)
	out := p.text()
	t.Log(out[max(0, len(out)-1500):])
	if code == 0 {
		t.Fatalf("código de salida 0 tras un fallo de arranque")
	}
	if !strings.Contains(out, "could not start the monolith") || !strings.Contains(out, "KMS") {
		t.Errorf("la salida no nombra el fallo ni el servicio")
	}
	if canDial(fmt.Sprintf("127.0.0.1:%d", httpsPort)) {
		t.Errorf("el proxy escucha tras el fallo")
	}
	if m := regexp.MustCompile(`launched docker: Postgres \(container ([0-9a-f]{12})\)`).FindStringSubmatch(out); m != nil && containerExists(t, m[1]) {
		t.Errorf("el PostgreSQL del monolito (%s) sigue existiendo", m[1])
	}
	if m := regexp.MustCompile(`releasing runtime directory (\S+)`).FindStringSubmatch(out); m == nil {
		t.Errorf("no se liberó el directorio propio")
	} else if _, err := os.Stat(m[1]); !os.IsNotExist(err) {
		t.Errorf("el directorio propio %s sigue existiendo", m[1])
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
