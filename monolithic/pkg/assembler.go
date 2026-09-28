package pkg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	lamassu "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devprofile"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/utils/gindump"
	log "github.com/sirupsen/logrus"
)

// Monolith es un monolito ensamblado: los puertos del proxy y a qué puerto
// de servicio lleva cada prefijo.
type Monolith struct {
	HTTPPort    int
	HTTPSPort   int
	ProxyRoutes map[string]int
}

func RunMonolithicLamassuPKI(conf MonolithicConfig) (int, int, error) {
	m, err := AssembleMonolith(conf)
	if err != nil {
		return -1, -1, err
	}
	return m.HTTPPort, m.HTTPSPort, nil
}

// AssembleMonolith monta los servicios y el proxy en modo HTTP.
func AssembleMonolith(conf MonolithicConfig) (*Monolith, error) {
	log.SetLevel(log.PanicLevel)
	if conf.AssemblyMode == Http {
		// Initialize OTel SDK once at the very beginning, before any HTTP clients are created
		// This ensures trace context propagation works correctly across all services
		sdk.InitOtelSDK(context.Background(), "Lamassu-Monolithic", conf.OtelConfig)

		apiInfo := models.APIServiceInfo{
			Version:   "-",
			BuildSHA:  "-",
			BuildTime: "-",
		}

		profile, err := devprofile.Build(conf)
		if err != nil {
			return nil, fmt.Errorf("invalid multitenant profile: %w", err)
		}
		tenantRoutes, err := newTenantRouteOptionsBuilder(conf)
		if err != nil {
			return nil, err
		}

		// Hasta la tarea 12 de la spec 009, sin RuntimeDir los ficheros del
		// proxy siguen en el directorio de trabajo.
		proxyCertFile := filepath.Join(conf.Multitenant.RuntimeDir, "proxy.crt")
		proxyKeyFile := filepath.Join(conf.Multitenant.RuntimeDir, "proxy.key")

		key, _ := chelpers.GenerateRSAKey(2048)
		keyPem, _ := chelpers.PrivateKeyToPEM(key)
		os.WriteFile(proxyKeyFile, []byte(keyPem), 0600)

		crt, err := chelpers.GenerateSelfSignedCertificate(key, "proxy-lms-test")
		if err != nil {
			panic(fmt.Sprintf("could not create self signed cert: %s", err))
		}

		crtPem := chelpers.CertificateToPEM(crt)
		os.WriteFile(proxyCertFile, []byte(crtPem), 0600)

		kmsRoutes, err := tenantRoutes.build("KMS", profile.KMS.Server)
		if err != nil {
			return nil, fmt.Errorf("could not assemble KMS Service: %s", err)
		}
		_, kmsPort, err := lamassu.AssembleKMSServiceWithHTTPServer(profile.KMS, apiInfo, kmsRoutes)
		if err != nil {
			return nil, fmt.Errorf("could not assemble KMS Service: %s", err)
		}

		// Los clientes SDK entre servicios usan la config de devprofile:
		// auth_mode mtls con el certificado del servicio que llama, contra el
		// listener interno del destino (009 T9). El destino marca la petición
		// como INTERNAL_SERVICE y opera en el tenant del contexto propagado.
		kmsSDK := func(cfg cconfig.HTTPClient, serviceID, src string) (services.KMSService, error) {
			cli, err := sdk.BuildHTTPClient(cfg, chelpers.SetupLogger(cconfig.Info, serviceID, "LMS SDK - KMS Client"))
			if err != nil {
				return nil, fmt.Errorf("could not build %s KMS client: %w", serviceID, err)
			}
			return sdk.NewHttpKMSClient(sdk.HttpClientWithSourceHeaderInjector(cli, src), sdk.BuildURL(cfg)), nil
		}

		caRoutes, err := tenantRoutes.build("CA", profile.CA.Server)
		if err != nil {
			return nil, fmt.Errorf("could not assemble CA Service: %s", err)
		}
		caKMS, err := kmsSDK(profile.CA.KMSClient.HTTPClient, "CA", models.CASource)
		if err != nil {
			return nil, fmt.Errorf("could not assemble CA Service: %s", err)
		}
		_, _, caPort, err := lamassu.AssembleCAServiceWithHTTPServer(profile.CA, caKMS, apiInfo, caRoutes)
		if err != nil {
			return nil, fmt.Errorf("could not assemble CA Service: %s", err)
		}

		caConnection := cconfig.HTTPConnection{BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: caPort}, Protocol: cconfig.HTTP, BasePath: ""}
		caSDK := func(cfg cconfig.HTTPClient, serviceID, src string) (services.CAService, error) {
			cli, err := sdk.BuildHTTPClient(cfg, chelpers.SetupLogger(cconfig.Info, serviceID, "LMS SDK - CA Client"))
			if err != nil {
				return nil, fmt.Errorf("could not build %s CA client: %w", serviceID, err)
			}
			return sdk.NewHttpCAClient(sdk.HttpClientWithSourceHeaderInjector(cli, src), sdk.BuildURL(cfg)), nil
		}
		// Solo para el conector AWS IoT, que aún no es multitenant (P6).
		caSDKBuilder := func(serviceID, src string) services.CAService {
			lCAClient := chelpers.SetupLogger(cconfig.Info, serviceID, "LMS SDK - CA Client")
			caHttpCli, err := sdk.BuildHTTPClient(cconfig.HTTPClient{
				LogLevel:       cconfig.Info,
				AuthMode:       cconfig.NoAuth,
				HTTPConnection: caConnection,
			}, lCAClient)
			if err != nil {
				log.Fatalf("could not build HTTP CA Client: %s", err)
			}

			return sdk.NewHttpCAClient(
				sdk.HttpClientWithSourceHeaderInjector(caHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", caConnection.Protocol, caConnection.Hostname, caConnection.BasePath, caConnection.Port),
			)
		}

		vaRoutes, err := tenantRoutes.build("VA", profile.VA.Server)
		if err != nil {
			return nil, fmt.Errorf("could not assemble VA Service: %s", err)
		}
		vaCA, err := caSDK(profile.VA.CAClient.HTTPClient, "VA", models.VASource)
		if err != nil {
			return nil, fmt.Errorf("could not assemble VA Service: %s", err)
		}
		vaKMS, err := kmsSDK(profile.VA.KMSClient.HTTPClient, "VA", models.VASource)
		if err != nil {
			return nil, fmt.Errorf("could not assemble VA Service: %s", err)
		}
		_, _, vaPort, err := lamassu.AssembleVAServiceWithHTTPServer(profile.VA, vaCA, vaKMS, apiInfo, vaRoutes)
		if err != nil {
			return nil, fmt.Errorf("could not assemble VA Service: %s", err)
		}

		devRoutes, err := tenantRoutes.build("Device Manager", profile.DeviceManager.Server)
		if err != nil {
			return nil, fmt.Errorf("could not assemble Device Manager Service: %s", err)
		}
		devCA, err := caSDK(profile.DeviceManager.CAClient.HTTPClient, "Device Manager", models.DeviceManagerSource)
		if err != nil {
			return nil, fmt.Errorf("could not assemble Device Manager Service: %s", err)
		}
		_, devPort, err := lamassu.AssembleDeviceManagerServiceWithHTTPServer(profile.DeviceManager, devCA, apiInfo, devRoutes)
		if err != nil {
			return nil, fmt.Errorf("could not assemble Device Manager Service: %s", err)
		}

		devMngrConnection := cconfig.HTTPConnection{BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: devPort}, Protocol: cconfig.HTTP, BasePath: ""}

		devMngrSDK := func(cfg cconfig.HTTPClient, serviceID, src string) (services.DeviceManagerService, error) {
			cli, err := sdk.BuildHTTPClient(cfg, chelpers.SetupLogger(cconfig.Info, serviceID, "LMS SDK - DevManager Client"))
			if err != nil {
				return nil, fmt.Errorf("could not build %s Device Manager client: %w", serviceID, err)
			}
			return sdk.NewHttpDeviceManagerClient(sdk.HttpClientWithSourceHeaderInjector(cli, src), sdk.BuildURL(cfg)), nil
		}
		// Solo para el conector AWS IoT, que aún no es multitenant (P6).
		deviceMngrSDKBuilder := func(serviceID, src string) services.DeviceManagerService {
			lDevMngrClient := chelpers.SetupLogger(cconfig.Info, serviceID, "LMS SDK - DevManager Client")
			devMngrHttpCli, err := sdk.BuildHTTPClient(cconfig.HTTPClient{
				LogLevel:       cconfig.Info,
				AuthMode:       cconfig.NoAuth,
				HTTPConnection: devMngrConnection,
			}, lDevMngrClient)
			if err != nil {
				log.Fatalf("could not build HTTP DevManager Client: %s", err)
			}

			return sdk.NewHttpDeviceManagerClient(
				sdk.HttpClientWithSourceHeaderInjector(devMngrHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", devMngrConnection.Protocol, devMngrConnection.Hostname, devMngrConnection.BasePath, devMngrConnection.Port),
			)
		}
		dmsConf := profile.DMS
		dmsConf.DownstreamCertificateFile = proxyCertFile
		dmsRoutes, err := tenantRoutes.build("DMS Manager", dmsConf.Server)
		if err != nil {
			return nil, fmt.Errorf("could not assemble DMS Manager Service: %s", err)
		}
		dmsCA, err := caSDK(dmsConf.CAClient.HTTPClient, "DMS Manager", models.DMSManagerSource)
		if err != nil {
			return nil, fmt.Errorf("could not assemble DMS Manager Service: %s", err)
		}
		dmsDevMngr, err := devMngrSDK(dmsConf.DevManagerClient.HTTPClient, "DMS Manager", models.DMSManagerSource)
		if err != nil {
			return nil, fmt.Errorf("could not assemble DMS Manager Service: %s", err)
		}
		_, dmsPort, err := lamassu.AssembleDMSManagerServiceWithHTTPServer(dmsConf, dmsCA, dmsDevMngr, apiInfo, dmsRoutes)
		if err != nil {
			return nil, fmt.Errorf("could not assemble DMS Manager Service: %s", err)
		}

		dmsMngrConnection := cconfig.HTTPConnection{BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: dmsPort}, Protocol: cconfig.HTTP, BasePath: ""}

		// Solo para el conector AWS IoT, que aún no es multitenant (P6).
		dmsMngrSDKBuilder := func(serviceID, src string) services.DMSManagerService {
			lDMSMngrClient := chelpers.SetupLogger(cconfig.Info, serviceID, "LMS SDK - DMSManager Client")
			dmsMngrHttpCli, err := sdk.BuildHTTPClient(cconfig.HTTPClient{
				LogLevel:       cconfig.Info,
				AuthMode:       cconfig.NoAuth,
				HTTPConnection: dmsMngrConnection,
			}, lDMSMngrClient)
			if err != nil {
				log.Fatalf("could not build HTTP DMSManager Client: %s", err)
			}

			return sdk.NewHttpDMSManagerClient(
				sdk.HttpClientWithSourceHeaderInjector(dmsMngrHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", dmsMngrConnection.Protocol, dmsMngrConnection.Hostname, dmsMngrConnection.BasePath, dmsMngrConnection.Port),
			)
		}
		alertsRoutes, err := tenantRoutes.build("Alerts", profile.Alerts.Server)
		if err != nil {
			return nil, fmt.Errorf("could not assemble Alerts Service: %s", err)
		}
		_, alertsPort, err := lamassu.AssembleAlertsServiceWithHTTPServer(profile.Alerts, apiInfo, alertsRoutes)
		if err != nil {
			return nil, fmt.Errorf("could not assemble Alerts Service: %s", err)
		}

		tmRoutes, err := tenantRoutes.build("Tenant Manager", profile.TenantManager.Server)
		if err != nil {
			return nil, fmt.Errorf("could not assemble Tenant Manager Service: %s", err)
		}
		_, tmPort, err := lamassu.AssembleTenantManagerServiceWithHTTPServer(profile.TenantManager, apiInfo, tmRoutes)
		if err != nil {
			return nil, fmt.Errorf("could not assemble Tenant Manager Service: %s", err)
		}

		if conf.AWSIoTManager.Enabled {
			err = AssembleAWSIoT(conf, caSDKBuilder, dmsMngrSDKBuilder, deviceMngrSDKBuilder)
			if err != nil {
				return nil, fmt.Errorf("could not assemble AWS IoT Manager: %s", err)
			}
		}

		engine := gin.New()
		engine.Use(gin.Recovery(), clientCertsToHeaderUsingEnvoyStyle())

		routeMaps := make(map[string]func(c *gin.Context))
		proxyRoutes := make(map[string]int)
		routeList := make([]string, 0)

		addRouteMap := func(serviceName, servicePath string, servicePort int) {
			subpath := servicePath
			subpath = strings.TrimSuffix(subpath, "/")
			color.Set(color.BgCyan)
			color.Set(color.FgWhite)
			fmt.Printf("  (HTTPS)  0.0.0.0:%d%s*  --> %s 127.0.0.1:%d\n", conf.GatewayPortHttps, servicePath, serviceName, servicePort)
			fmt.Printf("  (HTTP)   0.0.0.0:%d%s*  --> %s 127.0.0.1:%d\n", conf.GatewayPortHttp, servicePath, serviceName, servicePort)
			color.Unset()
			fmt.Printf("\n")
			proxyRoutes[servicePath] = servicePort
			routeMaps[servicePath] = func(c *gin.Context) {
				remote, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", servicePort))
				if err != nil {
					panic(err)
				}
				proxyUrl := strings.TrimPrefix(c.Param("proxyPath"), subpath)
				proxyUrl = strings.TrimSuffix(proxyUrl, "/")
				//emulate envoy config by generating rand request id as HTTP header to the upstream service
				c.Request.Header.Add("x-request-id", uuid.NewString())
				proxy := httputil.NewSingleHostReverseProxy(remote)
				//Define the director func
				//This is a good place to log, for example
				proxy.Director = func(req *http.Request) {
					req.Header = c.Request.Header
					req.Host = remote.Host
					req.URL.Scheme = remote.Scheme
					req.URL.Host = remote.Host
					req.URL.Path = proxyUrl
				}
				proxy.ServeHTTP(c.Writer, c.Request)
			}
			for k := range routeMaps {
				routeList = append(routeList, k)
			}
		}

		defaultHander := func(c *gin.Context) {
			remote, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", conf.UIPort))
			if err != nil {
				panic(err)
			}
			//emulate envoy config by generating rand request id as HTTP header to the upstream service
			c.Request.Header.Add("x-request-id", uuid.NewString())
			proxy := httputil.NewSingleHostReverseProxy(remote)
			//Define the director func
			//This is a good place to log, for example
			proxy.Director = func(req *http.Request) {
				req.Header = c.Request.Header
				req.Host = remote.Host
				req.URL.Scheme = remote.Scheme
				req.URL.Host = remote.Host
			}
			proxy.ServeHTTP(c.Writer, c.Request)
		}

		addRouteMap("KMS", "/api/kms/", kmsPort)
		addRouteMap("CA", "/api/ca/", caPort)
		addRouteMap("Dev Manager", "/api/devmanager/", devPort)
		addRouteMap("DMS Manager", "/api/dmsmanager/", dmsPort)
		addRouteMap("VA", "/api/va/", vaPort)
		addRouteMap("Alerts", "/api/alerts/", alertsPort)
		// Mismo prefijo que el gateway de Helm: /api/tenants/api/v2/... llega
		// al Tenant Manager como /api/v2/...
		addRouteMap("Tenant Manager", "/api/tenants/", tmPort)

		buildReverseProxyGlobalHandler := func(engine *gin.Engine) {
			proxy := func(c *gin.Context) {
				var realProxy func(c *gin.Context)
				foundPath := false
				path := c.Param("proxyPath")
				for _, route := range routeList {
					if strings.HasPrefix(path, route) {
						realProxy = routeMaps[route]
						foundPath = true
						break
					}
				}
				gindump.Dump()
				if foundPath {
					realProxy(c)
				} else {
					defaultHander(c)
				}
			}
			engine.Any("/*proxyPath", proxy)
		}

		buildReverseProxyGlobalHandler(engine)

		listenerHttps, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", conf.GatewayPortHttps))
		if err != nil {
			log.Fatalf("could not get Gateway net Listener: %s", err)
		}

		listenerHttp, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", conf.GatewayPortHttp))
		if err != nil {
			log.Fatalf("could not get Gateway net Listener: %s", err)
		}

		usedHttpsPort := listenerHttps.Addr().(*net.TCPAddr).Port
		usedHttpPort := listenerHttp.Addr().(*net.TCPAddr).Port

		go func() {
			serverHttps := http.Server{
				Handler: engine,
				Addr:    fmt.Sprintf(":%d", conf.GatewayPortHttps),
				TLSConfig: &tls.Config{
					ClientAuth: tls.RequestClientCert,
				},
				ReadHeaderTimeout: time.Second * 10,
			}

			log.Fatal(serverHttps.ServeTLS(listenerHttps, proxyCertFile, proxyKeyFile))
		}()

		go func() {
			serverHttp := http.Server{
				Handler:           engine,
				Addr:              fmt.Sprintf(":%d", conf.GatewayPortHttp),
				ReadHeaderTimeout: time.Second * 10,
			}

			log.Fatal(serverHttp.Serve(listenerHttp))
		}()

		return &Monolith{HTTPPort: usedHttpPort, HTTPSPort: usedHttpsPort, ProxyRoutes: proxyRoutes}, nil
	}

	return nil, fmt.Errorf("unsupported mode")
}

func clientCertsToHeaderUsingEnvoyStyle() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS != nil {
			if len(c.Request.TLS.PeerCertificates) > 0 {
				fullChain := ""
				for _, crt := range c.Request.TLS.PeerCertificates {
					fullChain += chelpers.CertificateToPEM(crt)
				}
				chainURLEnc := url.QueryEscape(fullChain)
				c.Request.Header.Add("x-forwarded-client-cert", fmt.Sprintf("Chain=%q", chainURLEnc))
			}
		}

		c.Next()
	}
}
