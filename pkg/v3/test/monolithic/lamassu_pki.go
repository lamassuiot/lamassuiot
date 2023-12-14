package monolithic

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/lamassu"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	log "github.com/sirupsen/logrus"
)

func RunMonolithicLamassuPKI(conf config.MonolithicConfig) error {
	log.SetLevel(log.DebugLevel)
	if conf.AssemblyMode == config.Http {
		apiInfo := models.APIServiceInfo{
			Version:   "-",
			BuildSHA:  "-",
			BuildTime: "-",
		}

		key, _ := helpers.GenerateRSAKey(2048)
		keyPem, _ := helpers.PrivateKeyToPEM(key)
		os.WriteFile("proxy.key", []byte(keyPem), 0644)

		crt, err := helpers.GenerateSelfSignedCertificate(key, "proxy-lms-test")
		if err != nil {
			panic(fmt.Sprintf("could not create self signed cert: %s", err))
		}

		crtPem := helpers.CertificateToPEM(crt)
		os.WriteFile("proxy.crt", []byte(crtPem), 0644)

		_, caPort, err := lamassu.AssembleCAServiceWithHTTPServer(config.CAConfig{
			BaseConfig: config.BaseConfig{
				Logs: config.BaseConfigLogging{
					Level: config.Info,
				},
				Server: config.HttpServer{
					LogLevel:           config.Info,
					HealthCheckLogging: true,
					ListenAddress:      "0.0.0.0",
					Port:               0,
					Protocol:           config.HTTP,
				},
				AMQPConnection: conf.AMQPConnection,
			},
			Storage:          conf.Storage,
			CryptoEngines:    conf.CryptoEngines,
			CryptoMonitoring: conf.CryptoMonitoring,
			VAServerDomain:   fmt.Sprintf("https://%s/api/va", conf.Domain),
		}, apiInfo)
		if err != nil {
			return fmt.Errorf("could not assemble CA Service: %s", err)
		}

		caConnection := config.HTTPConnection{BasicConnection: config.BasicConnection{Hostname: "127.0.0.1", Port: caPort}, Protocol: config.HTTP, BasePath: ""}
		lCAClient := helpers.ConfigureLogger(config.Info, "LMS SDK - CA Client")
		caHttpCli, err := clients.BuildHTTPClient(config.HTTPClient{
			LogLevel:       config.Info,
			AuthMode:       config.NoAuth,
			HTTPConnection: caConnection,
		}, lCAClient)
		if err != nil {
			log.Fatalf("could not build HTTP CA Client: %s", err)
		}

		caSDKBuilder := func(src string) services.CAService {
			return clients.NewHttpCAClient(
				clients.HttpClientWithSourceHeaderInjector(caHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", caConnection.Protocol, caConnection.Hostname, caConnection.BasePath, caConnection.Port),
			)
		}

		_, _, vaPort, err := lamassu.AssembleVAServiceWithHTTPServer(config.VAconfig{
			BaseConfig: config.BaseConfig{
				Logs: config.BaseConfigLogging{
					Level: config.Info,
				},
				Server: config.HttpServer{
					LogLevel:           config.Info,
					HealthCheckLogging: true,
					ListenAddress:      "0.0.0.0",
					Port:               0,
					Protocol:           config.HTTP,
				},
				AMQPConnection: conf.AMQPConnection,
			},
		}, caSDKBuilder(models.VASource), apiInfo)
		if err != nil {
			return fmt.Errorf("could not assemble VA Service: %s", err)
		}

		_, devPort, err := lamassu.AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
			BaseConfig: config.BaseConfig{
				Logs: config.BaseConfigLogging{
					Level: config.Info,
				},
				Server: config.HttpServer{
					LogLevel:           config.Info,
					HealthCheckLogging: true,
					ListenAddress:      "0.0.0.0",
					Port:               0,
					Protocol:           config.HTTP,
				},
				AMQPConnection: conf.AMQPConnection,
			},
			Storage: conf.Storage,
		}, caSDKBuilder(models.DeviceManagerSource), apiInfo)
		if err != nil {
			return fmt.Errorf("could not assemble Device Manager Service: %s", err)
		}

		devMngrConnection := config.HTTPConnection{BasicConnection: config.BasicConnection{Hostname: "127.0.0.1", Port: devPort}, Protocol: config.HTTP, BasePath: ""}
		lDevMngrClient := helpers.ConfigureLogger(config.Info, "LMS SDK - DevManager Client")
		devMngrHttpCli, err := clients.BuildHTTPClient(config.HTTPClient{
			LogLevel:       config.Info,
			AuthMode:       config.NoAuth,
			HTTPConnection: devMngrConnection,
		}, lDevMngrClient)
		if err != nil {
			log.Fatalf("could not build HTTP DevManager Client: %s", err)
		}

		deviceMngrSDKBuilder := func(src string) services.DeviceManagerService {
			return clients.NewHttpDeviceManagerClient(
				clients.HttpClientWithSourceHeaderInjector(devMngrHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", devMngrConnection.Protocol, devMngrConnection.Hostname, devMngrConnection.BasePath, devMngrConnection.Port),
			)
		}
		_, dmsPort, err := lamassu.AssembleDMSManagerServiceWithHTTPServer(config.DMSconfig{
			BaseConfig: config.BaseConfig{
				Logs: config.BaseConfigLogging{
					Level: config.Info,
				},
				Server: config.HttpServer{
					LogLevel:           config.Info,
					HealthCheckLogging: true,
					ListenAddress:      "0.0.0.0",
					Port:               0,
					Protocol:           config.HTTP,
				},
				AMQPConnection: conf.AMQPConnection,
			},
			DownstreamCertificateFile: "proxy.crt",
			Storage:                   conf.Storage,
		}, caSDKBuilder(models.DMSManagerSource), deviceMngrSDKBuilder(models.DMSManagerSource), apiInfo)
		if err != nil {
			return fmt.Errorf("could not assemble DMS Manager Service: %s", err)
		}

		dmsMngrConnection := config.HTTPConnection{BasicConnection: config.BasicConnection{Hostname: "127.0.0.1", Port: dmsPort}, Protocol: config.HTTP, BasePath: ""}
		lDMSMngrClient := helpers.ConfigureLogger(config.Info, "LMS SDK - DMSManager Client")
		dmsMngrHttpCli, err := clients.BuildHTTPClient(config.HTTPClient{
			LogLevel:       config.Info,
			AuthMode:       config.NoAuth,
			HTTPConnection: dmsMngrConnection,
		}, lDMSMngrClient)
		if err != nil {
			log.Fatalf("could not build HTTP DMSManager Client: %s", err)
		}

		dmsMngrSDKBuilder := func(src string) services.DMSManagerService {
			return clients.NewHttpDMSManagerClient(
				clients.HttpClientWithSourceHeaderInjector(dmsMngrHttpCli, src),
				fmt.Sprintf("%s://%s%s:%d", dmsMngrConnection.Protocol, dmsMngrConnection.Hostname, dmsMngrConnection.BasePath, dmsMngrConnection.Port),
			)
		}
		_, alertsPort, err := lamassu.AssembleAlertsServiceWithHTTPServer(config.AlertsConfig{
			BaseConfig: config.BaseConfig{
				Logs: config.BaseConfigLogging{
					Level: config.Info,
				},
				Server: config.HttpServer{
					LogLevel:           config.Info,
					HealthCheckLogging: true,
					ListenAddress:      "0.0.0.0",
					Port:               0,
					Protocol:           config.HTTP,
				},
				AMQPConnection: conf.AMQPConnection,
			},
			Storage: conf.Storage,
		}, apiInfo)
		if err != nil {
			return fmt.Errorf("could not assemble Alerts Service: %s", err)
		}

		if conf.AWSIoTManager.Enabled {
			_, err = lamassu.AssembleAWSIoTManagerService(config.IotAWS{
				BaseConfig: config.BaseConfig{
					Logs: config.BaseConfigLogging{
						Level: config.Info,
					},
					AMQPConnection: conf.AMQPConnection,
				},
				ConnectorID:  conf.AWSIoTManager.ConnectorID,
				AWSSDKConfig: conf.AWSIoTManager.AWSSDKConfig,
			}, caSDKBuilder(models.AWSIoTSource(conf.AWSIoTManager.ConnectorID)), dmsMngrSDKBuilder(models.AWSIoTSource(conf.AWSIoTManager.ConnectorID)), deviceMngrSDKBuilder(models.AWSIoTSource(conf.AWSIoTManager.ConnectorID)))
			if err != nil {
				return fmt.Errorf("could not assemble AWS IoT Manager: %s", err)
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

		go func() {
			// log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", conf.GatewayPort), engine))
			server := http.Server{
				Handler: engine,
				Addr:    fmt.Sprintf(":%d", conf.GatewayPort),
				TLSConfig: &tls.Config{
					ClientAuth: tls.RequestClientCert,
				},
			}

			log.Fatal(server.ListenAndServeTLS("proxy.crt", "proxy.key"))
		}()

	}

	return nil
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
