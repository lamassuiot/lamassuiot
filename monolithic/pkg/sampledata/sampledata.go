package sampledata

// Datos de ejemplo del monolito multitenant (spec 009, tarea 11; requisitos
// 9.1–9.3). Con -sample-data el monolito provisiona (o reutiliza) la
// organización y el tenant «Demo» por el Tenant Manager, da pki_admin a una
// identidad de servicio y crea los datos por las rutas v2 de ese tenant, con
// tokens del emisor local.
//
// Los clientes SDK van al puerto público de cada servicio, sin prefijo, y no
// al proxy: el SDK solo promueve /v1/... a /api/v2/tenants/<id>/... cuando la
// URL base no tiene ruta, así que con la base del proxy (…/api/ca) la petición
// acabaría en v1 (503). Es lo mismo que hacen los servicios entre sí.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devissuer"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/sirupsen/logrus"
)

const (
	DemoOrganizationName = "Demo"
	DemoTenantName       = "Demo"
	// DemoAdminSubject es el tenant_admin inicial del tenant de demostración.
	DemoAdminSubject = "demo-admin"
	// SampleDataSubject es la identidad de servicio con pki_admin que crea
	// perfiles, CAs y certificados.
	SampleDataSubject = "sample-data"
	// DemoOperatorSubject es la identidad con operator que crea los
	// dispositivos y les asocia su certificado. Por la matriz RBAC de G2,
	// pki_admin no tiene device.write ni identity.bind, y dms.write es de
	// tenant_admin (lo usa demo-admin); una identidad tiene un solo rol por
	// tenant.
	DemoOperatorSubject = "demo-operator"
	// ProvisionerSubject es el provisioner por defecto del emisor local
	// (devruntime.DefaultProvisionerSubject).
	ProvisionerSubject = "provisioner"

	source = "monolith-sample-data"
)

// Targets son las URL base (sin ruta) de cada servicio.
type Targets struct {
	CA, KMS, DeviceManager, DMSManager, TenantManager string
}

// TargetsFromProxyRoutes construye los Targets con los puertos públicos de
// los servicios que devuelve el ensamblador (prefijo del proxy → puerto).
func TargetsFromProxyRoutes(host string, routes map[string]int) Targets {
	base := func(prefix string) string {
		return fmt.Sprintf("http://%s:%d", host, routes[prefix])
	}
	return Targets{
		CA:            base("/api/ca/"),
		KMS:           base("/api/kms/"),
		DeviceManager: base("/api/devmanager/"),
		DMSManager:    base("/api/dmsmanager/"),
		TenantManager: base("/api/tenants/"),
	}
}

// Options son las entradas de PopulateSampleData.
type Options struct {
	Targets Targets
	// Issuer es el iss de las identidades de demostración (el emisor local).
	Issuer string
	// Tokens pide un token al emisor local.
	Tokens func(devissuer.TokenRequest) (string, error)
	// HTTPClient para el Tenant Manager y los SDK. Vacío: uno con timeout.
	HTTPClient *http.Client
}

// Result es el tenant de demostración y los avisos de los datos que no se
// pudieron crear (por ejemplo, porque ya existían).
type Result struct {
	OrganizationID string
	TenantID       string
	Warnings       []string
}

type clients struct {
	ca      services.CAService
	kms     services.KMSService
	dms     services.DMSManagerService // tenant_admin: dms.write
	devices services.DeviceManagerService
	binder  services.DMSManagerService // operator: identity.bind
}

// PopulateSampleData provisiona el tenant de demostración y crea en él los
// datos de ejemplo. Un error nombra el paso que falló; quien llama decide si
// sigue (el monolito solo avisa, requisito 9.3).
func PopulateSampleData(ctx context.Context, logger *logrus.Entry, opts Options) (*Result, error) {
	if opts.Tokens == nil || opts.Issuer == "" {
		return nil, errors.New("sample data: the local token issuer is required (-dev-issuer)")
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	tm := tenantManager{base: opts.Targets.TenantManager, client: httpClient, tokens: opts.Tokens}

	logger.Infof("Provisioning demo organization %q and tenant %q...", DemoOrganizationName, DemoTenantName)
	orgID, err := tm.ensureOrganization(ctx)
	if err != nil {
		return nil, fmt.Errorf("sample data: step 'demo organization': %w", err)
	}
	result := &Result{OrganizationID: orgID}
	if result.TenantID, err = tm.ensureTenant(ctx, orgID, opts.Issuer); err != nil {
		return result, fmt.Errorf("sample data: step 'demo tenant': %w", err)
	}
	for _, grant := range []struct{ subject, role string }{
		{SampleDataSubject, "pki_admin"},
		{DemoOperatorSubject, "operator"},
	} {
		if err := tm.ensureMembership(ctx, result.TenantID, opts.Issuer, grant.subject, grant.role); err != nil {
			return result, fmt.Errorf("sample data: step '%s membership for %s': %w", grant.role, grant.subject, err)
		}
	}
	logger.Infof("Demo tenant %s (organization %s): %s is tenant_admin, %s is pki_admin and %s is operator",
		result.TenantID, orgID, DemoAdminSubject, SampleDataSubject, DemoOperatorSubject)

	// Un token por rol. KMS: por la matriz RBAC de G2 solo concede sus
	// operaciones a un pki_admin con actor SERVICE y el scope de la operación.
	tokens := map[string]devissuer.TokenRequest{
		"pki_admin":         {Subject: SampleDataSubject, ActorType: "HUMAN", TTL: "1h"},
		"pki_admin/SERVICE": {Subject: SampleDataSubject, ActorType: "SERVICE", Scope: "key.import", TTL: "1h"},
		"tenant_admin":      {Subject: DemoAdminSubject, ActorType: "HUMAN", TTL: "1h"},
		"operator":          {Subject: DemoOperatorSubject, ActorType: "HUMAN", TTL: "1h"},
	}
	clientsFor := map[string]*http.Client{}
	for role, req := range tokens {
		token, err := opts.Tokens(req)
		if err != nil {
			return result, fmt.Errorf("sample data: step 'token for %s (%s)': %w", req.Subject, role, err)
		}
		cli := &http.Client{Timeout: httpClient.Timeout, Transport: httpClient.Transport}
		clientsFor[role] = sdk.HttpClientWithCustomHeaders(cli, "Authorization", "Bearer "+token)
	}
	c := clients{
		ca:      sdk.NewHttpCAClient(clientsFor["pki_admin"], opts.Targets.CA),
		kms:     sdk.NewHttpKMSClient(clientsFor["pki_admin/SERVICE"], opts.Targets.KMS),
		dms:     sdk.NewHttpDMSManagerClient(clientsFor["tenant_admin"], opts.Targets.DMSManager),
		devices: sdk.NewHttpDeviceManagerClient(clientsFor["operator"], opts.Targets.DeviceManager),
		binder:  sdk.NewHttpDMSManagerClient(clientsFor["operator"], opts.Targets.DMSManager),
	}

	tenantCtx := core.WithTenantContext(ctx, core.TenantContext{
		OrganizationID: orgID,
		TenantID:       result.TenantID,
		ActorID:        SampleDataSubject,
		ActorType:      "HUMAN",
		CorrelationID:  uuid.NewString(),
		Source:         source,
		Validated:      true,
	})
	recorder, populateLogger := recordWarnings(logger)
	if err := populate(tenantCtx, populateLogger, c); err != nil {
		return result, fmt.Errorf("sample data: step 'create data in the demo tenant': %w", err)
	}
	result.Warnings = recorder.warnings
	return result, nil
}

// tenantManager llama a la API v2 del Tenant Manager con tokens del emisor.
type tenantManager struct {
	base   string
	client *http.Client
	tokens func(devissuer.TokenRequest) (string, error)
}

type organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type tenant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type membership struct {
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

func (tm tenantManager) ensureOrganization(ctx context.Context) (string, error) {
	var list struct {
		Organizations []organization `json:"organizations"`
	}
	if err := tm.call(ctx, ProvisionerSubject, http.MethodGet, "/api/v2/provisioning/organizations", nil, http.StatusOK, &list); err != nil {
		return "", err
	}
	for _, org := range list.Organizations {
		if org.Name == DemoOrganizationName {
			return org.ID, nil
		}
	}
	var created organization
	err := tm.call(ctx, ProvisionerSubject, http.MethodPost, "/api/v2/provisioning/organizations",
		map[string]string{"name": DemoOrganizationName}, http.StatusCreated, &created)
	return created.ID, err
}

func (tm tenantManager) ensureTenant(ctx context.Context, orgID, issuer string) (string, error) {
	var list struct {
		Tenants []tenant `json:"tenants"`
	}
	if err := tm.call(ctx, ProvisionerSubject, http.MethodGet, "/api/v2/provisioning/tenants?organization_id="+url.QueryEscape(orgID), nil, http.StatusOK, &list); err != nil {
		return "", err
	}
	for _, t := range list.Tenants {
		if t.Name != DemoTenantName {
			continue
		}
		// El tenant ya existe: su tenant_admin tiene que ser el demo-admin de
		// este emisor. El issuer del emisor local incluye su puerto, que
		// cambia en cada arranque; con un PostgreSQL externo reutilizado, el
		// tenant de un arranque anterior pertenece a otro issuer.
		if ok, err := tm.hasMembership(ctx, DemoAdminSubject, t.ID, "tenant_admin"); err != nil {
			return "", err
		} else if !ok {
			return "", fmt.Errorf("tenant %q (%s) already exists but %s of issuer %s is not its tenant_admin "+
				"(the local issuer changes on every start; use a fresh database to recreate the sample data)", DemoTenantName, t.ID, DemoAdminSubject, issuer)
		}
		return t.ID, nil
	}
	var created tenant
	err := tm.call(ctx, ProvisionerSubject, http.MethodPost, "/api/v2/provisioning/tenants", map[string]any{
		"organization_id": orgID,
		"name":            DemoTenantName,
		"initial_admin":   map[string]string{"issuer": issuer, "subject": DemoAdminSubject},
	}, http.StatusCreated, &created)
	return created.ID, err
}

// ensureMembership da role a subject en el tenant (lo hace demo-admin, su
// tenant_admin), salvo que ya lo tenga.
func (tm tenantManager) ensureMembership(ctx context.Context, tenantID, issuer, subject, role string) error {
	if ok, err := tm.hasMembership(ctx, subject, tenantID, role); err != nil || ok {
		return err
	}
	return tm.call(ctx, DemoAdminSubject, http.MethodPost, "/api/v2/tenants/"+url.PathEscape(tenantID)+"/memberships",
		map[string]string{"issuer": issuer, "subject": subject, "role": role}, http.StatusCreated, nil)
}

func (tm tenantManager) hasMembership(ctx context.Context, subject, tenantID, role string) (bool, error) {
	var list struct {
		Memberships []membership `json:"memberships"`
	}
	if err := tm.call(ctx, subject, http.MethodGet, "/api/v2/me/memberships", nil, http.StatusOK, &list); err != nil {
		return false, err
	}
	for _, m := range list.Memberships {
		if m.TenantID == tenantID && m.Role == role && m.Status == "ACTIVE" {
			return true, nil
		}
	}
	return false, nil
}

func (tm tenantManager) call(ctx context.Context, subject, method, path string, body any, want int, out any) error {
	token, err := tm.tokens(devissuer.TokenRequest{Subject: subject, ActorType: "HUMAN"})
	if err != nil {
		return fmt.Errorf("token for %s: %w", subject, err)
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, tm.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := tm.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s as %s: status %d: %.300s", method, path, subject, resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s %s: invalid response: %w", method, path, err)
	}
	return nil
}

// warningRecorder guarda los avisos de populate: cada dato que no se pudo
// crear se avisa y se sigue con el resto, como antes.
type warningRecorder struct{ warnings []string }

func (r *warningRecorder) Levels() []logrus.Level { return []logrus.Level{logrus.WarnLevel} }

func (r *warningRecorder) Fire(entry *logrus.Entry) error {
	r.warnings = append(r.warnings, entry.Message)
	return nil
}

// recordWarnings devuelve un logger con la misma salida que logger que además
// guarda los avisos, sin añadir un hook al logger compartido.
func recordWarnings(logger *logrus.Entry) (*warningRecorder, *logrus.Entry) {
	recorder := &warningRecorder{}
	l := logrus.New()
	l.SetOutput(logger.Logger.Out)
	l.SetFormatter(logger.Logger.Formatter)
	l.SetLevel(logger.Logger.Level)
	l.AddHook(recorder)
	return recorder, l.WithFields(logger.Data)
}
