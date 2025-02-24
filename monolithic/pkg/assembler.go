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
			CryptoMonitoring: conf.CryptoMonitoring,
			VAServerDomains: []string{
				fmt.Sprintf("%s:%d/api/va", conf.Domain, conf.GatewayPortHttp),
			},
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
			VADomains: []string{
				fmt.Sprintf("%s:%d/api/va", conf.Domain, conf.GatewayPortHttp),
			},
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
		buildReverseProxyHandler := func(engine *gin.Engine, serviceName, servicePath string, servicePort int) {
			subpath := servicePath
			subpath = strings.TrimSuffix(subpath, "/")

			color.Set(color.BgCyan)
			color.Set(color.FgWhite)
			fmt.Printf("  (HTTPS) 	0.0.0.0:%d%s*  --> %s 127.0.0.1:%d\n", conf.GatewayPortHttps, servicePath, serviceName, servicePort)
			fmt.Printf("  (HTTP)	0.0.0.0:%d%s*  --> %s 127.0.0.1:%d\n", conf.GatewayPortHttp, servicePath, serviceName, servicePort)
			color.Unset()
			fmt.Printf("\n")

			proxy := func(c *gin.Context) {
				remote, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", servicePort))
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

			engine.Any(fmt.Sprintf("%s/*proxyPath", subpath), proxy)
		}

		buildReverseProxyHandler(engine, "CA", "/api/ca/", caPort)
		buildReverseProxyHandler(engine, "Dev Manager", "/api/devmanager/", devPort)
		buildReverseProxyHandler(engine, "DMS Manager", "/api/dmsmanager/", dmsPort)
		buildReverseProxyHandler(engine, "VA", "/api/va/", vaPort)
		buildReverseProxyHandler(engine, "Alerts", "/api/alerts/", alertsPort)

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
