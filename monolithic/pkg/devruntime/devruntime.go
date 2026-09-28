// Package devruntime genera los artefactos de arranque del monolito
// multitenant (spec 009): la CA del monolito (TLS del emisor local), la CA
// interna y un certificado por servicio (mTLS entre servicios), y el emisor
// local de tokens. Devuelve las entradas multitenant de MonolithicConfig que
// dependen de ellos. Todo se escribe en un directorio propio con permisos
// 0700/0600 y nada en el directorio de trabajo.
package devruntime

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devissuer"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devpki"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

// DefaultProvisionerSubject es el sub del provisioner del emisor local.
const DefaultProvisionerSubject = "provisioner"

// Options son las entradas del arranque que no se generan.
type Options struct {
	// Dir es el directorio de los ficheros generados. Se crea con 0700.
	Dir string
	// DevIssuer activa el emisor local (P2, activo por defecto en el monolito).
	DevIssuer bool
	// Audience de los tokens. Vacía: devissuer.DefaultAudience.
	Audience string
	// ExternalIssuers son los IdP externos (-issuer).
	ExternalIssuers []cconfig.HttpServerJWTIssuer
	// ExternalCAFiles son las CA que firman el JWKS de los IdP externos (-issuer-ca-file).
	ExternalCAFiles []string
}

// Runtime son los artefactos generados en un arranque.
type Runtime struct {
	Dir string
	// CA es la CA del monolito: firma el TLS del emisor local.
	CA *devpki.CA
	// InternalCA es la CA interna: firma los certificados de los listeners
	// internos y de los clientes SDK entre servicios.
	InternalCA *devpki.CA
	// Issuer es el emisor local, o nil si está desactivado.
	Issuer *devissuer.Issuer
	// Multitenant son las entradas de MonolithicConfig.Multitenant que
	// dependen de este arranque.
	Multitenant monoconfig.MultitenantConfig
}

// Start genera los artefactos y arranca el emisor local si se pide.
func Start(opts Options) (*Runtime, error) {
	if opts.Dir == "" {
		return nil, errors.New("devruntime: runtime directory is required")
	}
	if !opts.DevIssuer && len(opts.ExternalIssuers) == 0 {
		return nil, errors.New("devruntime: the local token issuer is disabled and no external issuer is configured: at least one JWT issuer is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("devruntime: create runtime directory: %w", err)
	}
	if err := os.Chmod(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("devruntime: restrict runtime directory: %w", err)
	}

	rt := &Runtime{Dir: opts.Dir}
	var err error
	if rt.CA, err = devpki.NewCA("Lamassu monolith CA"); err != nil {
		return nil, err
	}
	caFile := filepath.Join(opts.Dir, "monolith-ca.crt")
	if err := devpki.WriteFile(caFile, rt.CA.CertPEM()); err != nil {
		return nil, fmt.Errorf("devruntime: write monolith CA: %w", err)
	}

	internalTLS, err := rt.writeInternalTLS()
	if err != nil {
		return nil, err
	}

	issuers := make([]cconfig.HttpServerJWTIssuer, 0, len(opts.ExternalIssuers)+1)
	trusted := []string{}
	if opts.DevIssuer {
		leaf, err := rt.CA.Issue("lamassu-dev-issuer")
		if err != nil {
			return nil, err
		}
		if rt.Issuer, err = devissuer.Start(devissuer.Options{TLSCertificate: leaf.TLS, Audience: opts.Audience}); err != nil {
			return nil, err
		}
		issuers = append(issuers, cconfig.HttpServerJWTIssuer{Issuer: rt.Issuer.Issuer(), JWKSURL: rt.Issuer.JWKSURL()})
		trusted = append(trusted, caFile)
	}
	issuers = append(issuers, opts.ExternalIssuers...)
	trusted = append(trusted, opts.ExternalCAFiles...)

	rt.Multitenant = monoconfig.MultitenantConfig{
		Audience:           opts.Audience,
		Issuers:            issuers,
		JWKSTrustedCAFiles: trusted,
		InternalTLS:        internalTLS,
		RuntimeDir:         opts.Dir,
	}
	return rt, nil
}

// Close para el emisor local.
func (rt *Runtime) Close() error {
	if rt == nil || rt.Issuer == nil {
		return nil
	}
	return rt.Issuer.Close()
}

// DefaultProvisioners es el provisioner del emisor local, o ninguno si está
// desactivado.
func (rt *Runtime) DefaultProvisioners() []config.TenantManagerProvisioner {
	if rt.Issuer == nil {
		return nil
	}
	return []config.TenantManagerProvisioner{{Issuer: rt.Issuer.Issuer(), Subject: DefaultProvisionerSubject}}
}

func (rt *Runtime) writeInternalTLS() (monoconfig.InternalTLSConfig, error) {
	var err error
	if rt.InternalCA, err = devpki.NewCA("Lamassu monolith internal CA"); err != nil {
		return monoconfig.InternalTLSConfig{}, err
	}
	dir := filepath.Join(rt.Dir, "internal")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return monoconfig.InternalTLSConfig{}, fmt.Errorf("devruntime: create internal TLS directory: %w", err)
	}
	out := monoconfig.InternalTLSConfig{
		// No «ca.crt»: ese nombre es el del certificado del servicio CA.
		CAFile:   filepath.Join(dir, "internal-ca.crt"),
		Services: map[monoconfig.Service]monoconfig.InternalTLSFiles{},
		Ports:    map[monoconfig.Service]int{},
	}
	if err := devpki.WriteFile(out.CAFile, rt.InternalCA.CertPEM()); err != nil {
		return monoconfig.InternalTLSConfig{}, fmt.Errorf("devruntime: write internal CA: %w", err)
	}
	ports, err := reserveLoopbackPorts(len(monoconfig.AllServices))
	if err != nil {
		return monoconfig.InternalTLSConfig{}, err
	}
	for i, svc := range monoconfig.AllServices {
		leaf, err := rt.InternalCA.Issue("lamassu-" + string(svc))
		if err != nil {
			return monoconfig.InternalTLSConfig{}, err
		}
		files := monoconfig.InternalTLSFiles{
			CertFile: filepath.Join(dir, string(svc)+".crt"),
			KeyFile:  filepath.Join(dir, string(svc)+".key"),
		}
		if err := devpki.WriteFile(files.CertFile, leaf.CertPEM); err != nil {
			return monoconfig.InternalTLSConfig{}, err
		}
		if err := devpki.WriteFile(files.KeyFile, leaf.KeyPEM); err != nil {
			return monoconfig.InternalTLSConfig{}, err
		}
		out.Services[svc] = files
		out.Ports[svc] = ports[i]
	}
	return out, nil
}

// reserveLoopbackPorts elige n puertos libres y distintos en 127.0.0.1 (D7).
// Los clientes SDK de un servicio necesitan el puerto interno del destino
// antes de montarlo, y el backend no devuelve el puerto real del listener
// interno cuando se configura 0. Entre el cierre y el Listen del servicio hay
// una carrera pequeña: si otro proceso toma el puerto, el montaje falla con
// «address already in use» y el monolito no arranca (fallo explícito).
func reserveLoopbackPorts(n int) ([]int, error) {
	listeners := make([]net.Listener, 0, n)
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("devruntime: reserve internal port: %w", err)
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}
