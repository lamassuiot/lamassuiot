package pkg

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	lamassu "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/utils/gindump"
	log "github.com/sirupsen/logrus"
)

func RunMonolithicLamassuPKI(conf MonolithicConfig) (int, int, error) {
	log.SetLevel(log.PanicLevel)
	if conf.AssemblyMode == Http {
		apiInfo := models.APIServiceInfo{
			Version:   "-",
			BuildSHA:  "-",
			BuildTime: "-",
		}

		key, _ := chelpers.GenerateRSAKey(2048)
		keyPem, _ := chelpers.PrivateKeyToPEM(key)
		os.WriteFile("proxy.key", []byte(keyPem), 0600)

		crt, err := chelpers.GenerateSelfSignedCertificate(key, "proxy-lms-test")
		if err != nil {
			panic(fmt.Sprintf("could not create self signed cert: %s", err))
		}

		crtPem := chelpers.CertificateToPEM(crt)
		os.WriteFile("proxy.crt", []byte(crtPem), 0600)

		vaDomains := []string{}
		for _, domain := range conf.Domains {
			vaDomains = append(vaDomains, fmt.Sprintf("%s:%d/api/va", domain, conf.GatewayPortHttp))
		}

		_, _, caPort, err := lamassu.AssembleCAServiceWithHTTPServer(config.CAConfig{
			Logs: cconfig.Logging{
				Level: conf.Logs.Level,
			},
			Server: cconfig.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           cconfig.HTTP,
			},
			PublisherEventBus: conf.PublisherEventBus,
			Storage:           conf.Storage,
			CryptoEngineConfig: config.CryptoEngines{
				LogLevel:      cconfig.Info,
				DefaultEngine: conf.CryptoEngines[0].ID,
				CryptoEngines: conf.CryptoEngines,
			},
			CertificateMonitoringJob: conf.Monitoring,
			VAServerDomains:          vaDomains,
		}, apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble CA Service: %s", err)
		}

		caConnection := cconfig.HTTPConnection{BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: caPort}, Protocol: cconfig.HTTP, BasePath: ""}
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

		_, _, vaPort, err := lamassu.AssembleVAServiceWithHTTPServer(config.VAconfig{
			Logs: cconfig.Logging{
				Level: conf.Logs.Level,
			},
			Server: cconfig.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           cconfig.HTTP,
			},
			FilesystemStorage: cconfig.FSStorageConfig{
				ID:   "fs",
				Type: cconfig.LocalFilesystem,
				Config: map[string]interface{}{
					"storage_directory": conf.VAStorageDir,
				},
			},
			CRLMonitoringJob:   conf.Monitoring,
			SubscriberEventBus: conf.SubscriberEventBus,
			PublisherEventBus:  conf.PublisherEventBus,
			Storage:            conf.Storage,
			VADomains:          vaDomains,
		}, caSDKBuilder("VA", models.VASource), apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble VA Service: %s", err)
		}

		_, devPort, err := lamassu.AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
			Logs: cconfig.Logging{
				Level: conf.Logs.Level,
			},
			Server: cconfig.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           cconfig.HTTP,
			},
			PublisherEventBus:  conf.PublisherEventBus,
			SubscriberEventBus: conf.SubscriberEventBus,
			Storage:            conf.Storage,
		}, caSDKBuilder("Device Manager", models.DeviceManagerSource), apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble Device Manager Service: %s", err)
		}

		devMngrConnection := cconfig.HTTPConnection{BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: devPort}, Protocol: cconfig.HTTP, BasePath: ""}

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
		_, dmsPort, err := lamassu.AssembleDMSManagerServiceWithHTTPServer(config.DMSconfig{
			Logs: cconfig.Logging{
				Level: conf.Logs.Level,
			},
			Server: cconfig.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           cconfig.HTTP,
			},
			PublisherEventBus:         conf.PublisherEventBus,
			DownstreamCertificateFile: "proxy.crt",
			Storage:                   conf.Storage,
		}, caSDKBuilder("DMS Manager", models.DMSManagerSource), deviceMngrSDKBuilder("DMS Manager", models.DMSManagerSource), apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble DMS Manager Service: %s", err)
		}

		dmsMngrConnection := cconfig.HTTPConnection{BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: dmsPort}, Protocol: cconfig.HTTP, BasePath: ""}

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
		_, alertsPort, err := lamassu.AssembleAlertsServiceWithHTTPServer(config.AlertsConfig{
			Logs: cconfig.Logging{
				Level: conf.Logs.Level,
			},
			Server: cconfig.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           cconfig.HTTP,
			},
			SubscriberEventBus: conf.SubscriberEventBus,
			Storage:            conf.Storage,
		}, apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble Alerts Service: %s", err)
		}

		if conf.AWSIoTManager.Enabled {
			err = AssembleAWSIoT(conf, caSDKBuilder, dmsMngrSDKBuilder, deviceMngrSDKBuilder)
			if err != nil {
				return -1, -1, fmt.Errorf("could not assemble AWS IoT Manager: %s", err)
			}
		}

		engine := gin.New()
		engine.Use(gin.Recovery(), clientCertsToHeaderUsingEnvoyStyle())

		routeMaps := make(map[string]func(c *gin.Context))
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
			routeMaps[servicePath] = func(c *gin.Context) {
				remote, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", servicePort))
				if err != nil {
					panic(err)
				}
				proxyUrl := strings.TrimPrefix(c.Param("proxyPath"), subpath)
				proxyUrl = strings.TrimSuffix(proxyUrl, "/")
				fmt.Printf("Proxy URL: %s\n", proxyUrl)
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
				req.URL.Path = c.Param("proxyPath")
			}
			proxy.ServeHTTP(c.Writer, c.Request)
		}

		addRouteMap("CA", "/api/ca/", caPort)
		addRouteMap("Dev Manager", "/api/devmanager/", devPort)
		addRouteMap("DMS Manager", "/api/dmsmanager/", dmsPort)
		addRouteMap("VA", "/api/va/", vaPort)
		addRouteMap("Alerts", "/api/alerts/", alertsPort)

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
		usedHttpPort := listenerHttps.Addr().(*net.TCPAddr).Port

		go func() {
			serverHttps := http.Server{
				Handler: engine,
				Addr:    fmt.Sprintf(":%d", conf.GatewayPortHttps),
				TLSConfig: &tls.Config{
					ClientAuth: tls.RequestClientCert,
				},
				ReadHeaderTimeout: time.Second * 10,
			}

			log.Fatal(serverHttps.ServeTLS(listenerHttps, "proxy.crt", "proxy.key"))
		}()

		go func() {
			serverHttp := http.Server{
				Handler:           engine,
				Addr:              fmt.Sprintf(":%d", conf.GatewayPortHttp),
				ReadHeaderTimeout: time.Second * 10,
			}

			log.Fatal(serverHttp.Serve(listenerHttp))
		}()

		return usedHttpPort, usedHttpsPort, nil
	}

	return -1, -1, fmt.Errorf("unsupported mode")
}

func clientCertsToHeaderUsingEnvoyStyle() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS != nil {
			if len(c.Request.TLS.PeerCertificates) > 0 {
				crtChain := []string{}
				for _, crt := range c.Request.TLS.PeerCertificates {
					crtPem := chelpers.CertificateToPEM(crt)
					crtURLEnc := url.QueryEscape(crtPem)
					crtChain = append(crtChain, fmt.Sprintf("Cert=%s", crtURLEnc))
				}
				c.Request.Header.Add("x-forwarded-client-cert", strings.Join(crtChain, ";"))
			}
		}

		c.Next()
	}
}
