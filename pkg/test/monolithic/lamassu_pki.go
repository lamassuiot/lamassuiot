package monolithic

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	lamassu "github.com/lamassuiot/lamassuiot/v2/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/clients"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	log "github.com/sirupsen/logrus"
)

func RunMonolithicLamassuPKI(conf config.MonolithicConfig) (int, error) {
	log.SetLevel(log.PanicLevel)
	if conf.AssemblyMode == config.Http {
		apiInfo := models.APIServiceInfo{
			Version:   "-",
			BuildSHA:  "-",
			BuildTime: "-",
		}

		key, _ := helpers.GenerateRSAKey(2048)
		keyPem, _ := helpers.PrivateKeyToPEM(key)
		os.WriteFile("proxy.key", []byte(keyPem), 0600)

		crt, err := helpers.GenerateSelfSignedCertificate(key, "proxy-lms-test")
		if err != nil {
			panic(fmt.Sprintf("could not create self signed cert: %s", err))
		}

		crtPem := helpers.CertificateToPEM(crt)
		os.WriteFile("proxy.crt", []byte(crtPem), 0600)

		_, _, caPort, err := lamassu.AssembleCAServiceWithHTTPServer(config.CAConfig{
			Logs: config.BaseConfigLogging{
				Level: conf.Logs.Level,
			},
			Server: config.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           config.HTTP,
			},
			PublisherEventBus: conf.PublisherEventBus,
			Storage:           conf.Storage,
			CryptoEngines:     conf.CryptoEngines,
			CryptoMonitoring:  conf.CryptoMonitoring,
			VAServerDomain:    fmt.Sprintf("%s/api/va", conf.Domain),
		}, apiInfo)
		if err != nil {
			return -1, fmt.Errorf("could not assemble CA Service: %s", err)
		}

		caConnection := config.HTTPConnection{BasicConnection: config.BasicConnection{Hostname: "127.0.0.1", Port: caPort}, Protocol: config.HTTP, BasePath: ""}
		caSDKBuilder := func(serviceID, src string) services.CAService {
			lCAClient := helpers.SetupLogger(config.Info, serviceID, "LMS SDK - CA Client")
			caHttpCli, err := clients.BuildHTTPClient(config.HTTPClient{
				LogLevel:       config.Info,
				AuthMode:       config.NoAuth,
				HTTPConnection: caConnection,
			}, lCAClient)
			if err != nil {
				log.Fatalf("could not build HTTP CA Client: %s", err)
			}

			return clients.NewHttpCAClient(
				clients.HttpClientWithSourceHeaderInjector(caHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", caConnection.Protocol, caConnection.Hostname, caConnection.BasePath, caConnection.Port),
			)
		}

		_, _, vaPort, err := lamassu.AssembleVAServiceWithHTTPServer(config.VAconfig{
			Logs: config.BaseConfigLogging{
				Level: conf.Logs.Level,
			},
			Server: config.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           config.HTTP,
			},
		}, caSDKBuilder("VA", models.VASource), apiInfo)
		if err != nil {
			return -1, fmt.Errorf("could not assemble VA Service: %s", err)
		}

		_, devPort, err := lamassu.AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
			Logs: config.BaseConfigLogging{
				Level: conf.Logs.Level,
			},
			Server: config.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           config.HTTP,
			},
			PublisherEventBus:  conf.PublisherEventBus,
			SubscriberEventBus: conf.SubscriberEventBus,
			Storage:            conf.Storage,
		}, caSDKBuilder("Device Manager", models.DeviceManagerSource), apiInfo)
		if err != nil {
			return -1, fmt.Errorf("could not assemble Device Manager Service: %s", err)
		}

		devMngrConnection := config.HTTPConnection{BasicConnection: config.BasicConnection{Hostname: "127.0.0.1", Port: devPort}, Protocol: config.HTTP, BasePath: ""}

		deviceMngrSDKBuilder := func(serviceID, src string) services.DeviceManagerService {
			lDevMngrClient := helpers.SetupLogger(config.Info, serviceID, "LMS SDK - DevManager Client")
			devMngrHttpCli, err := clients.BuildHTTPClient(config.HTTPClient{
				LogLevel:       config.Info,
				AuthMode:       config.NoAuth,
				HTTPConnection: devMngrConnection,
			}, lDevMngrClient)
			if err != nil {
				log.Fatalf("could not build HTTP DevManager Client: %s", err)
			}

			return clients.NewHttpDeviceManagerClient(
				clients.HttpClientWithSourceHeaderInjector(devMngrHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", devMngrConnection.Protocol, devMngrConnection.Hostname, devMngrConnection.BasePath, devMngrConnection.Port),
			)
		}
		_, dmsPort, err := lamassu.AssembleDMSManagerServiceWithHTTPServer(config.DMSconfig{
			Logs: config.BaseConfigLogging{
				Level: conf.Logs.Level,
			},
			Server: config.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           config.HTTP,
			},
			PublisherEventBus:         conf.PublisherEventBus,
			DownstreamCertificateFile: "proxy.crt",
			Storage:                   conf.Storage,
		}, caSDKBuilder("DMS Manager", models.DMSManagerSource), deviceMngrSDKBuilder("DMS Manager", models.DMSManagerSource), apiInfo)
		if err != nil {
			return -1, fmt.Errorf("could not assemble DMS Manager Service: %s", err)
		}

		dmsMngrConnection := config.HTTPConnection{BasicConnection: config.BasicConnection{Hostname: "127.0.0.1", Port: dmsPort}, Protocol: config.HTTP, BasePath: ""}

		dmsMngrSDKBuilder := func(serviceID, src string) services.DMSManagerService {
			lDMSMngrClient := helpers.SetupLogger(config.Info, serviceID, "LMS SDK - DMSManager Client")
			dmsMngrHttpCli, err := clients.BuildHTTPClient(config.HTTPClient{
				LogLevel:       config.Info,
				AuthMode:       config.NoAuth,
				HTTPConnection: dmsMngrConnection,
			}, lDMSMngrClient)
			if err != nil {
				log.Fatalf("could not build HTTP DMSManager Client: %s", err)
			}

			return clients.NewHttpDMSManagerClient(
				clients.HttpClientWithSourceHeaderInjector(dmsMngrHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", dmsMngrConnection.Protocol, dmsMngrConnection.Hostname, dmsMngrConnection.BasePath, dmsMngrConnection.Port),
			)
		}
		_, alertsPort, err := lamassu.AssembleAlertsServiceWithHTTPServer(config.AlertsConfig{
			Logs: config.BaseConfigLogging{
				Level: conf.Logs.Level,
			},
			Server: config.HttpServer{
				LogLevel:           conf.Logs.Level,
				HealthCheckLogging: true,
				ListenAddress:      "0.0.0.0",
				Port:               0,
				Protocol:           config.HTTP,
			},
			SubscriberEventBus: conf.SubscriberEventBus,
			Storage:            conf.Storage,
		}, apiInfo)
		if err != nil {
			return -1, fmt.Errorf("could not assemble Alerts Service: %s", err)
		}

		if conf.AWSIoTManager.Enabled {
			_, err = lamassu.AssembleAWSIoTManagerService(config.IotAWS{
				Logs: config.BaseConfigLogging{
					Level: conf.Logs.Level,
				},
				SubscriberEventBus: conf.SubscriberEventBus,
				ConnectorID:        conf.AWSIoTManager.ConnectorID,
				AWSSDKConfig:       conf.AWSIoTManager.AWSSDKConfig,
			}, caSDKBuilder("AWS IoT Connector", models.AWSIoTSource(conf.AWSIoTManager.ConnectorID)), dmsMngrSDKBuilder("AWS IoT Connector", models.AWSIoTSource(conf.AWSIoTManager.ConnectorID)), deviceMngrSDKBuilder("AWS IoT Connector", models.AWSIoTSource(conf.AWSIoTManager.ConnectorID)))
			if err != nil {
				return -1, fmt.Errorf("could not assemble AWS IoT Manager: %s", err)
			}
		}

		engine := gin.New()
		engine.Use(gin.Recovery(), clientCertsToHeaderUsingEnvoyStyle())
		buildReverseProxyHandler := func(engine *gin.Engine, serviceName, servicePath string, servicePort int) {
			subpath := servicePath
			subpath = strings.TrimSuffix(subpath, "/")

			color.Set(color.BgCyan)
			color.Set(color.FgWhite)
			fmt.Printf("  0.0.0.0:%d%s*  --> %s 127.0.0.1:%d  ", conf.GatewayPort, servicePath, serviceName, servicePort)
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

		listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", conf.GatewayPort))
		if err != nil {
			log.Fatalf("could not get Gateway net Listener: %s", err)
		}

		usedPort := listener.Addr().(*net.TCPAddr).Port

		go func() {
			// log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", conf.GatewayPort), engine))

			server := http.Server{
				Handler: engine,
				Addr:    fmt.Sprintf(":%d", conf.GatewayPort),
				TLSConfig: &tls.Config{
					ClientAuth: tls.RequestClientCert,
				},
			}

			log.Fatal(server.ServeTLS(listener, "proxy.crt", "proxy.key"))
		}()

		return usedPort, nil
	}

	return -1, fmt.Errorf("unsupported mode")
}

func clientCertsToHeaderUsingEnvoyStyle() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS != nil {
			if len(c.Request.TLS.PeerCertificates) > 0 {
				crtChain := []string{}
				for _, crt := range c.Request.TLS.PeerCertificates {
					crtPem := helpers.CertificateToPEM(crt)
					crtURLEnc := url.QueryEscape(crtPem)
					crtChain = append(crtChain, fmt.Sprintf("Cert=%s", crtURLEnc))
				}
				c.Request.Header.Add("x-forwarded-client-cert", strings.Join(crtChain, ";"))
			}
		}

		c.Next()
	}
}
