package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/fatih/color"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devruntime"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devstorage"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/eventbus/inmemory"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/sampledata"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
)

const readyToPKI = `
 ________   _______    ________   ________       ___    ___      _________   ________          ________   ___  __     ___
|\   __  \ |\  ___ \  |\   __  \ |\   ___ \     |\  \  /  /|    |\___   ___\|\   __  \        |\   __  \ |\  \|\  \  |\  \
\ \  \|\  \\ \   __/| \ \  \|\  \\ \  \_|\ \    \ \  \/  / /    \|___ \  \_|\ \  \|\  \       \ \  \|\  \\ \  \/  /|_\ \  \
 \ \   _  _\\ \  \_|/__\ \   __  \\ \  \ \\ \    \ \    / /          \ \  \  \ \  \\\  \       \ \   ____\\ \   ___  \\ \  \
  \ \  \\  \|\ \  \_|\ \\ \  \ \  \\ \  \_\\ \    \/  /  /            \ \  \  \ \  \\\  \       \ \  \___| \ \  \\ \  \\ \  \
   \ \__\\ _\ \ \_______\\ \__\ \__\\ \_______\ __/  / /               \ \__\  \ \_______\       \ \__\     \ \__\\ \__\\ \__\
    \|__|\|__| \|_______| \|__|\|__| \|_______||\___/ /                 \|__|   \|_______|        \|__|      \|__| \|__| \|__|
                                               \|___|/
`

const lamassuLogo = `
                                                              ..
                                                         ............
                                                        ....       ....
                                                       ...          ....
                                                       ...          ....
                                                       ...          ....
 ..... .........................
 ....                         ....                      ..............
      ....                       ....                  .................
     .....  ...................    ....                .....       .....
                             .....   .....             ....         ....
          .....  ...........    ....    ....           .....       .....
           ..             ....    .....   .....        .......   .......
                            ....     ....    ....      .......   .......
                               ....    ....    ....     ...............
                  ...........    ....     ....    ....    ..........    .
                ...............     ...     ....    ....     .....    ....
               ..................     ....     ...     ....        .......
              ......................                             .........
            ...    .......................................................
            ..     .......................................................
            ..     .......................................................
            ..     .......................................................
            ..     .......................................................
            ..    ............ ........                    ...... ........
           ..   ..........      .......                   ......   .......
         ..     .......           .....                   .....     ......
       .        .....              .....                 .....       .....
                .....               .....               .....        .....
                ..........           ........           .......       .......
                ...........          ..........        ..........     .........
`

type CryptoEngineOption string

const (
	AwsSecretsManager CryptoEngineOption = "aws-secrets"
	AwsKms            CryptoEngineOption = "aws-kms"
	Vault             CryptoEngineOption = "vault"
	Pkcs11            CryptoEngineOption = "pkcs11"
	Filesystem        CryptoEngineOption = "filesystem"
)

func main() {
	opts, err := parseOptions(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid options: %s\n", err)
		os.Exit(2)
	}
	os.Exit(runMonolith(opts))
}

// runMonolith arranca el monolito y lo mantiene en marcha hasta Ctrl+C. Un
// fallo de arranque (error o panic) libera lo que el propio proceso creó y
// devuelve 1; Ctrl+C lo libera y sale con 0 (requisito 1.4, 009 T12).
func runMonolith(opts *options) (code int) {
	res := &resources{}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		fmt.Println("ctrl+c triggered. Cleaning up")
		res.release()
		os.Exit(0)
	}()

	defer func() {
		if r := recover(); r != nil {
			printWColor(" !! Panic !! ", color.FgWhite, color.BgRed)
			fmt.Fprintln(os.Stderr, r)
			res.release()
			code = 1
		}
	}()

	if err := start(opts, res); err != nil {
		fmt.Fprintf(os.Stderr, "could not start the monolith: %s\n", err)
		res.release()
		return 1
	}
	select {}
}

// resources son las cosas que el proceso creó y debe liberar al salir: sus
// contenedores (cada uno por su propio recurso, nunca por etiqueta), el
// emisor local y el directorio propio. Se liberan en orden inverso y una sola
// vez; lo que se registra después de liberar se libera en el acto.
type resources struct {
	mu       sync.Mutex
	released bool
	releases []func()
}

func (r *resources) add(name string, release func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := func() {
		fmt.Printf(" -- releasing %s\n", name)
		release()
	}
	if r.released {
		f()
		return
	}
	r.releases = append(r.releases, f)
}

func (r *resources) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return
	}
	r.released = true
	fmt.Println("========== CLEANING UP ==========")
	for i := len(r.releases) - 1; i >= 0; i-- {
		r.releases[i]()
	}
}

// start lanza PostgreSQL y los servicios auxiliares, genera el directorio
// propio y monta el monolito. Devuelve nil cuando el proxy ya atiende.
func start(opts *options, res *resources) error {
	fmt.Println("===================== FLAGS ======================")
	fmt.Printf("Sample Data Enabled: %v\n", opts.sampleData)
	if opts.hsmModule != "" {
		fmt.Printf("HSM - PKCS11 Module Driver: %s\n", opts.hsmModule)
	}

	// By default, all crypto engines are enabled
	cryptoengineOptionsMap := map[CryptoEngineOption]struct{}{
		AwsSecretsManager: {},
		AwsKms:            {},
		Vault:             {},
		Pkcs11:            {},
		Filesystem:        {},
	}

	if opts.cryptoengineOptions != "" {
		var err error
		cryptoengineOptionsMap, err = parseCryptoEngineOptions(opts.cryptoengineOptions)
		if err != nil {
			return fmt.Errorf("could not parse crypto engine options: %w", err)
		}
		fmt.Printf("Crypto Engines: %v\n", cryptoengineOptionsMap)
	}

	fmt.Println("========== LAUNCHING AUXILIARY SERVICES ==========")

	// Register monolithic-specific engines
	if opts.useInMemoryEventbus {
		inmemory.Register()
	}

	fmt.Println("Storage Engine")
	// Solo PostgreSQL: parseOptions rechaza -sqlite (spec 009, P1).
	pg, err := devstorage.Start(context.Background(), devstorage.StartOptions{
		External:     opts.externalPostgres(),
		StandardPort: opts.standardDockerPorts,
	})
	if err != nil {
		return fmt.Errorf("could not start PostgreSQL: %w", err)
	}
	res.add("PostgreSQL", pg.Cleanup)
	postgresDescription := fmt.Sprintf("external %s:%d", pg.Admin.Hostname, pg.Admin.Port)
	if pg.Launched {
		postgresDescription = fmt.Sprintf("Docker container %.12s on %s:%d", pg.ContainerID, pg.Admin.Hostname, pg.Admin.Port)
		fmt.Printf(">> launched docker: Postgres (container %.12s)\n", pg.ContainerID)
		fmt.Printf(" \t-- postgres port: %d\n", pg.Admin.Port)
		fmt.Printf(" \t-- postgres admin user: %s\n", pg.Admin.Username)
		fmt.Printf(" \t-- postgres admin pass: %s\n", pg.Admin.Password)
	} else {
		fmt.Printf(">> using external Postgres %s:%d (admin user %s)\n", pg.Admin.Hostname, pg.Admin.Port, pg.Admin.Username)
	}

	storageLogger := chelpers.SetupLogger(cconfig.Info, "Monolithic", "PostgreSQL")
	prepared, err := devstorage.Prepare(context.Background(), storageLogger, pg.Admin)
	if err != nil {
		return fmt.Errorf("could not prepare PostgreSQL: %w", err)
	}
	storageConfig := prepared.Storage
	fmt.Printf(" \t-- services connect as: %s (random password, row level security applies)\n", devstorage.AppRole)

	fmt.Println("Crypto Engines")

	var vaultCryptoEngine cconfig.CryptoEngineConfig
	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		fmt.Println(">> launching docker: Hashicorp Vault ...")
		vaultSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Vault).Run(opts.standardDockerPorts)
		if err != nil {
			return fmt.Errorf("could not launch Hashicorp Vault: %w", err)
		}
		res.add("Hashicorp Vault", vaultSubsystem.AfterSuite)

		vaultCryptoEngine = vaultSubsystem.Config.(cconfig.CryptoEngineConfig)

		port := (vaultCryptoEngine.Config)["port"].(int)
		rootToken := (*vaultSubsystem.Extra)["rootToken"].(string)

		fmt.Printf(" \t-- vault port: %d\n", port)
		fmt.Printf(" \t-- vault root token: %s\n", rootToken)
	}

	_, awsSecretsEnabled := cryptoengineOptionsMap[AwsSecretsManager]
	_, awsKmsEnabled := cryptoengineOptionsMap[AwsKms]
	var awsBaseCryptoEngine cconfig.CryptoEngineConfig
	if awsSecretsEnabled || awsKmsEnabled {
		fmt.Println(">> launching docker: AWS Platform (Secrets Manager + KMS) ...")
		awsSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Aws).Run(opts.standardDockerPorts)
		if err != nil {
			return fmt.Errorf("could not launch AWS Platform: %w", err)
		}
		res.add("AWS Platform", awsSubsystem.AfterSuite)

		awsBaseCryptoEngine = awsSubsystem.Config.(cconfig.CryptoEngineConfig)
	}

	hsmModulePath := opts.hsmModule
	var pkcs11Cfg cconfig.CryptoEngineConfig
	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok && hsmModulePath != "" {
		fmt.Println(">> launching docker: SoftHSM ...")
		pkcs11SubsystemBuilder := subsystems.GetSubsystemBuilder[subsystems.ParametrizedSubsystem](subsystems.Pkcs11)
		pkcs11SubsystemBuilder.Prepare(map[string]interface{}{"hsmModulePath": hsmModulePath})
		pkcs11Subsystem, err := pkcs11SubsystemBuilder.Run(opts.standardDockerPorts)
		if err != nil {
			return fmt.Errorf("could not launch SoftHSM: %w", err)
		}
		res.add("SoftHSM", pkcs11Subsystem.AfterSuite)

		pkcs11Cfg = pkcs11Subsystem.Config.(cconfig.CryptoEngineConfig)
	}

	fmt.Println("Async Messaging Engine")
	eventBus := cconfig.EventBusEngine{
		LogLevel: cconfig.Trace,
		Enabled:  false,
		Provider: cconfig.Amqp,
		Config:   make(map[string]interface{}),
	}

	dlqEventBus := eventBus

	if !opts.disableEventbus && opts.useInMemoryEventbus {
		fmt.Println(">> using in-memory eventbus (no Docker required) ...")
		eventBus = cconfig.EventBusEngine{
			LogLevel: cconfig.Trace,
			Enabled:  true,
			Provider: "inmemory", // Custom provider for monolithic
			Config:   make(map[string]interface{}),
		}

		dlqEventBus = eventBus
		dlqEventBus.Config = make(map[string]interface{})

		fmt.Println(" \t-- inmemory eventbus: ephemeral GoChannel pub/sub")
	} else if !opts.disableEventbus && !opts.useAwsEventbus {
		fmt.Println(">> launching docker: RabbitMQ ...")
		rabbitmqSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.RabbitMQ).Run(opts.standardDockerPorts)
		if err != nil {
			return fmt.Errorf("could not launch RabbitMQ: %w", err)
		}
		res.add("RabbitMQ", rabbitmqSubsystem.AfterSuite)

		eventBus = rabbitmqSubsystem.Config.(cconfig.EventBusEngine)
		// make a copy for DLQ using deep copy

		adminPort := (*rabbitmqSubsystem.Extra)["adminPort"].(int)
		basicAuth := eventBus.Config["basic_auth"].(map[string]interface{})

		dlqEventBus = eventBus
		dlqEventBus.Config = deepCopy(eventBus.Config)
		dlqEventBus.Config["exchange"] = "lamassu-dlq"

		fmt.Printf(" \t-- rabbitmq UI port: %d\n", adminPort)
		fmt.Printf(" \t-- rabbitmq amqp port: %d\n", eventBus.Config["port"].(int))
		fmt.Printf(" \t-- rabbitmq user: %s\n", basicAuth["username"].(string))
		fmt.Printf(" \t-- rabbitmq pass: %s\n", basicAuth["password"].(cconfig.Password))
	} else if !opts.disableEventbus && opts.useAwsEventbus {
		fmt.Println(">> using AWS Eventbus")
		internalConfig := awsBaseCryptoEngine.Config

		eventBus = cconfig.EventBusEngine{
			LogLevel: cconfig.Trace,
			Enabled:  true,
			Provider: cconfig.AWSSqsSns,
			Config:   internalConfig,
		}
	}

	// La UI publicada (lamassu-ui) no se lanza: usa v1 sin OIDC (P4).

	fmt.Println("Identity (JWT)")
	// Directorio propio (0700) para certificados y claves generados al
	// arrancar; se borra al salir.
	runtimeDir, err := os.MkdirTemp("", "lamassu-monolith-")
	if err != nil {
		return fmt.Errorf("could not create runtime directory: %w", err)
	}
	res.add("runtime directory "+runtimeDir, func() { _ = os.RemoveAll(runtimeDir) })
	rt, err := devruntime.Start(devruntime.Options{
		Dir:             runtimeDir,
		DevIssuer:       opts.devIssuer,
		ExternalIssuers: opts.externalIssuers,
		ExternalCAFiles: opts.issuerCAFiles,
	})
	if err != nil {
		return fmt.Errorf("could not prepare the multitenant runtime: %w", err)
	}
	res.add("local token issuer", func() { _ = rt.Close() })
	multitenant := rt.Multitenant
	multitenant.Provisioners = opts.effectiveProvisioners(rt.DefaultProvisioners())
	multitenant.V1 = opts.v1Config()

	fmt.Println("========== READY TO LAUNCH MONOLITHIC PKI ==========")

	cryptoEnginesConfig := config.CryptoEngines{
		LogLevel: cconfig.Info,
	}

	cryptoEngines := []cconfig.CryptoEngineConfig{}

	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		vaultCryptoEngine.ID = "dockertest-hcpvault-kvv2"
		cryptoEnginesConfig.DefaultEngine = vaultCryptoEngine.ID
		cryptoEngines = append(cryptoEngines, vaultCryptoEngine)
	}

	if _, ok := cryptoengineOptionsMap[AwsKms]; ok {
		kmsCryptoEngine := cconfig.CryptoEngineConfig{
			ID:       "dockertest-localstack-kms",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.AWSKMSProvider,
			Config:   awsBaseCryptoEngine.Config,
		}
		cryptoEnginesConfig.DefaultEngine = kmsCryptoEngine.ID
		cryptoEngines = append(cryptoEngines, kmsCryptoEngine)
	}

	if _, ok := cryptoengineOptionsMap[AwsSecretsManager]; ok {
		secretsManagerCryptoEngine := cconfig.CryptoEngineConfig{
			ID:       "dockertest-localstack-smngr",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.AWSSecretsManagerProvider,
			Config:   awsBaseCryptoEngine.Config,
		}
		cryptoEnginesConfig.DefaultEngine = secretsManagerCryptoEngine.ID
		cryptoEngines = append(cryptoEngines, secretsManagerCryptoEngine)
	}

	if _, ok := cryptoengineOptionsMap[Filesystem]; ok {
		engineId := "filesystem-test-1"
		cryptoEngines = append(cryptoEngines, cconfig.CryptoEngineConfig{
			ID:       engineId,
			Metadata: make(map[string]interface{}),
			Type:     cconfig.FilesystemProvider,
			Config: map[string]interface{}{
				"storage_directory": "/tmp/gotest",
			},
		})
		cryptoEnginesConfig.DefaultEngine = engineId
	}

	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok {
		pkcs11Cfg.ID = "pkcs11-1"
		cryptoEnginesConfig.DefaultEngine = pkcs11Cfg.ID
		cryptoEngines = append(cryptoEngines, pkcs11Cfg)
	}

	cryptoEnginesConfig.CryptoEngines = cryptoEngines

	conf := pkg.MonolithicConfig{
		OtelConfig: cconfig.OTELConfig{
			Metrics: cconfig.OTELMetricsConfig{Enabled: false},
			Traces:  cconfig.OTELTracesConfig{Enabled: false},
			Logging: cconfig.OTELLoggingConfig{Enabled: false},
		},
		Logs:                  cconfig.Logging{Level: cconfig.Debug},
		VAStorageDir:          "/tmp/lamassuiot/va",
		SubscriberEventBus:    eventBus,
		SubscriberDLQEventBus: dlqEventBus,
		PublisherEventBus:     eventBus,
		Domains:               []string{"dev.lamassu.test", "localhost"},
		GatewayPortHttps:      opts.httpsPort,
		GatewayPortHttp:       opts.httpPort,
		ProxyListenAddress:    opts.listen,
		AssemblyMode:          pkg.Http,
		CryptoEngines:         cryptoEnginesConfig.CryptoEngines,
		Monitoring: cconfig.MonitoringJob{
			Enabled:   !opts.disableMonitor,
			Frequency: "2m",
		},
		Storage:            storageConfig,
		PopulateSampleData: opts.sampleData,
		Multitenant:        multitenant,
	}

	monolith, err := pkg.AssembleMonolith(conf)
	if err != nil {
		return err
	}

	fmt.Print(lamassuLogo)
	fmt.Print(readyToPKI)

	// Motores configurados. Antes se pedían a KMS por /v1/engines, pero v1
	// responde 503 salvo -v1-default-tenant y -v1-sunset (P3, 009 T10) y las
	// rutas v2 exigen un token con membership.
	fmt.Println("==================== Configured Crypto Engines =========================")
	for _, engine := range conf.CryptoEngines {
		fmt.Println(engine.ID)
	}
	fmt.Println("========================================================================")

	// Datos de ejemplo en el tenant «Demo», por v2 y con tokens del emisor
	// local (009 T11). Un fallo solo se avisa: el monolito sigue en marcha.
	if opts.sampleData {
		logger := chelpers.SetupLogger(cconfig.Info, "SampleData", "Populator")
		if rt.Issuer == nil {
			fmt.Println("Warning: -sample-data needs the local token issuer (-dev-issuer); no sample data created")
		} else {
			result, err := sampledata.PopulateSampleData(context.Background(), logger, sampledata.Options{
				Targets: sampledata.TargetsFromProxyRoutes("127.0.0.1", monolith.ProxyRoutes),
				Issuer:  rt.Issuer.Issuer(),
				Tokens:  rt.Issuer.Token,
			})
			if err != nil {
				fmt.Printf("Warning: failed to populate sample data: %v\n", err)
			} else {
				fmt.Printf(">> sample data in tenant %s (organization %s); identities: %s (tenant_admin), %s (pki_admin), %s (operator); %d warnings\n",
					result.TenantID, result.OrganizationID, sampledata.DemoAdminSubject, sampledata.SampleDataSubject, sampledata.DemoOperatorSubject, len(result.Warnings))
			}
		}
	}

	fmt.Print(renderBanner(bannerInfo{
		RuntimeDir:    runtimeDir,
		ListenAddress: monolith.ListenAddress,
		HTTPSPort:     monolith.HTTPSPort,
		HTTPPort:      monolith.HTTPPort,
		Issuers:       multitenant.Issuers,
		LocalIssuer:   rt.Issuer,
		Provisioners:  multitenant.Provisioners,
		V1:            multitenant.V1,
		Postgres:      postgresDescription,
		Warnings:      opts.warnings(),
	}))
	return nil
}

func parseCryptoEngineOptions(options string) (map[CryptoEngineOption]struct{}, error) {
	if options == "" {
		return nil, nil
	}
	// lowercase the options
	options = strings.ToLower(options)

	opts := make(map[CryptoEngineOption]struct{})
	for _, opt := range strings.Split(options, ",") {
		switch CryptoEngineOption(opt) {
		case AwsSecretsManager, AwsKms, Vault, Pkcs11, Filesystem:
			opts[CryptoEngineOption(opt)] = struct{}{}
		default:
			return nil, fmt.Errorf("invalid crypto engine option: %s", opt)
		}
	}
	return opts, nil
}

func printWColor(str string, fg, bg color.Attribute) {
	color.Set(fg)
	color.Set(bg)
	fmt.Println(str)
	color.Unset()
}

func deepCopy(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
