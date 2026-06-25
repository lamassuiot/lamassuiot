package pkg

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	authzapi "github.com/lamassuiot/authz/pkg/api"
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
		// Initialize OTel SDK once at the very beginning, before any HTTP clients are created
		// This ensures trace context propagation works correctly across all services
		sdk.InitOtelSDK(context.Background(), "Lamassu-Monolithic", conf.OtelConfig)

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

		// --- shared helpers ---

		svcLogs := cconfig.Logging{Level: conf.Logs.Level}
		svcServer := cconfig.HttpServer{
			LogLevel:           conf.Logs.Level,
			HealthCheckLogging: true,
			ListenAddress:      "0.0.0.0",
			Port:               0,
			Protocol:           cconfig.HTTP,
		}

		localConn := func(port int) cconfig.HTTPConnection {
			return cconfig.HTTPConnection{
				BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: port},
				Protocol:        cconfig.HTTP,
			}
		}

		baseURL := func(conn cconfig.HTTPConnection) string {
			return fmt.Sprintf("%s://%s%s:%d", conn.Protocol, conn.Hostname, conn.BasePath, conn.Port)
		}

		buildLocalClient := func(serviceID, src, label string, conn cconfig.HTTPConnection) *http.Client {
			l := chelpers.SetupLogger(cconfig.Info, serviceID, label)
			cli, err := sdk.BuildHTTPClient(cconfig.HTTPClient{
				LogLevel:       cconfig.Info,
				AuthMode:       cconfig.NoAuth,
				HTTPConnection: conn,
			}, l)
			if err != nil {
				log.Fatalf("could not build %s HTTP client: %s", label, err)
			}
			return sdk.HttpClientWithSourceHeaderInjector(cli, src)
		}

		// --- service assembly ---

		var authzClientConf config.AuthzClient
		var authzPort int
		if conf.AuthzConfig != nil {
			_, _, _, _, aPort, aErr := authzapi.AssembleAuthzServiceWithHTTPServer(*conf.AuthzConfig, models.APIServiceInfo{})
			if aErr != nil {
				return -1, -1, fmt.Errorf("could not assemble Authz Service: %s", aErr)
			}
			authzPort = aPort
			authzClientConf = config.AuthzClient{
				HTTPClient: cconfig.HTTPClient{
					LogLevel: cconfig.Info,
					AuthMode: cconfig.NoAuth,
					HTTPConnection: cconfig.HTTPConnection{
						Protocol:        cconfig.HTTP,
						BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: authzPort},
					},
				},
			}
		}

		_, kmsPort, err := lamassu.AssembleKMSServiceWithHTTPServer(config.KMSConfig{
			Logs:   svcLogs,
			Server: svcServer,
			CryptoEngineConfig: config.CryptoEngines{
				LogLevel:      cconfig.Info,
				DefaultEngine: conf.CryptoEngines[0].ID,
				CryptoEngines: conf.CryptoEngines,
			},
			PublisherEventBus: conf.PublisherEventBus,
			Storage:           conf.Storage,
			AuthzClient:       authzClientConf,
		}, apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble KMS Service: %s", err)
		}

		kmsConn := localConn(kmsPort)
		kmsSDKBuilder := func(serviceID, src string) services.KMSService {
			cli := buildLocalClient(serviceID, src, "LMS SDK - KMS Client", kmsConn)
			cli = sdk.HttpClientWithCustomHeaders(cli, "X-Principal-ID", "admin-mode")
			return sdk.NewHttpKMSClient(cli, baseURL(kmsConn))
		}

		_, _, caPort, err := lamassu.AssembleCAServiceWithHTTPServer(config.CAConfig{
			Logs:                     svcLogs,
			Server:                   svcServer,
			PublisherEventBus:        conf.PublisherEventBus,
			Storage:                  conf.Storage,
			CertificateMonitoringJob: conf.Monitoring,
			VAServerDomains:          vaDomains,
			AuthzClient:              authzClientConf,
		}, kmsSDKBuilder("KMS", models.KMSSource), apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble CA Service: %s", err)
		}

		caConn := localConn(caPort)
		caSDKBuilder := func(serviceID, src string) services.CAService {
			cli := buildLocalClient(serviceID, src, "LMS SDK - CA Client", caConn)
			cli = sdk.HttpClientWithCustomHeaders(cli, "X-Principal-ID", "admin-mode")
			return sdk.NewHttpCAClient(cli, baseURL(caConn))
		}

		_, _, vaPort, err := lamassu.AssembleVAServiceWithHTTPServer(config.VAconfig{
			Logs:   svcLogs,
			Server: svcServer,
			FilesystemStorage: cconfig.FSStorageConfig{
				ID:   "fs",
				Type: cconfig.LocalFilesystem,
				Config: map[string]interface{}{
					"storage_directory": conf.VAStorageDir,
				},
			},
			CRLMonitoringJob:      conf.Monitoring,
			SubscriberEventBus:    conf.SubscriberEventBus,
			SubscriberDLQEventBus: conf.SubscriberDLQEventBus,
			PublisherEventBus:     conf.PublisherEventBus,
			Storage:               conf.Storage,
			VADomains:             vaDomains,
			AuthzClient:           authzClientConf,
		}, caSDKBuilder("VA", models.VASource), kmsSDKBuilder("VA", models.VASource), apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble VA Service: %s", err)
		}

		_, devPort, err := lamassu.AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
			Logs:                  svcLogs,
			Server:                svcServer,
			PublisherEventBus:     conf.PublisherEventBus,
			SubscriberEventBus:    conf.SubscriberEventBus,
			SubscriberDLQEventBus: conf.SubscriberDLQEventBus,
			Storage:               conf.Storage,
			SSEEnabled:            conf.SSEEnabled,
			AuthzClient:           authzClientConf,
		}, caSDKBuilder("Device Manager", models.DeviceManagerSource), apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble Device Manager Service: %s", err)
		}

		devConn := localConn(devPort)
		deviceMngrSDKBuilder := func(serviceID, src string) services.DeviceManagerService {
			cli := buildLocalClient(serviceID, src, "LMS SDK - DevManager Client", devConn)
			cli = sdk.HttpClientWithCustomHeaders(cli, "X-Principal-ID", "admin-mode")
			return sdk.NewHttpDeviceManagerClient(cli, baseURL(devConn))
		}

		_, dmsPort, err := lamassu.AssembleDMSManagerServiceWithHTTPServer(config.DMSconfig{
			Logs:                      svcLogs,
			Server:                    svcServer,
			PublisherEventBus:         conf.PublisherEventBus,
			DownstreamCertificateFile: "proxy.crt",
			Storage:                   conf.Storage,
			AuthzClient:               authzClientConf,
		}, caSDKBuilder("DMS Manager", models.DMSManagerSource), deviceMngrSDKBuilder("DMS Manager", models.DMSManagerSource), apiInfo)
		if err != nil {
			return -1, -1, fmt.Errorf("could not assemble DMS Manager Service: %s", err)
		}

		dmsConn := localConn(dmsPort)
		dmsMngrSDKBuilder := func(serviceID, src string) services.DMSManagerService {
			cli := buildLocalClient(serviceID, src, "LMS SDK - DMSManager Client", dmsConn)
			cli = sdk.HttpClientWithCustomHeaders(cli, "X-Principal-ID", "admin-mode")
			return sdk.NewHttpDMSManagerClient(cli, baseURL(dmsConn))
		}

		_, alertsPort, err := lamassu.AssembleAlertsServiceWithHTTPServer(config.AlertsConfig{
			Logs:                  svcLogs,
			Server:                svcServer,
			SubscriberEventBus:    conf.SubscriberEventBus,
			SubscriberDLQEventBus: conf.SubscriberDLQEventBus,
			Storage:               conf.Storage,
			AuthzClient:           authzClientConf,
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

		corsConfig := cors.DefaultConfig()
		corsConfig.AllowAllOrigins = true
		corsConfig.AllowHeaders = []string{"*"}

		engine := gin.New()
		engine.Use(
			gin.Recovery(),
			cors.New(corsConfig),
			stripIncomingHeaders(),
			clientCertsToHeaderUsingEnvoyStyle(),
		)

		routeMaps := make(map[string]func(c *gin.Context))
		routeList := make([]string, 0)
		authzProxy := newMonolithicAuthzProxy(authzPort, authzProxyPrefixes(conf))

		// registerRoute registers a reverse proxy route. sourcePath is the incoming
		// path prefix; targetPath is the prefix to replace it with on the upstream.
		// Pass "" for targetPath to strip the prefix entirely (route to upstream root).
		// Pass sourcePath to forward the full path unchanged.
		// Pass any other value to rewrite the prefix (e.g. /api/wfx/nbi/ → /api/wfx/).
		registerRoute := func(serviceName, sourcePath string, servicePort int, targetPath string) {
			subpath := strings.TrimSuffix(sourcePath, "/")
			targetSubpath := strings.TrimSuffix(targetPath, "/")
			label := ""
			if targetPath != "" {
				if targetPath == sourcePath {
					label = " (path rewrite: keep)"
				} else {
					label = fmt.Sprintf(" (path rewrite: %s*)", targetSubpath)
				}
			}
			color.Set(color.BgCyan)
			color.Set(color.FgWhite)
			fmt.Printf("  (HTTPS)  0.0.0.0:%d%s*  --> %s 127.0.0.1:%d%s\n", conf.GatewayPortHttps, sourcePath, serviceName, servicePort, label)
			fmt.Printf("  (HTTP)   0.0.0.0:%d%s*  --> %s 127.0.0.1:%d%s\n", conf.GatewayPortHttp, sourcePath, serviceName, servicePort, label)
			color.Unset()
			fmt.Printf("\n")
			routeMaps[sourcePath] = func(c *gin.Context) {
				if authzProxy != nil && authzProxy.protects(c.Request.URL.Path) {
					statusCode, err := authzProxy.authorize(c.Request)
					if err != nil {
						log.WithError(err).WithFields(log.Fields{
							"method": c.Request.Method,
							"path":   c.Request.URL.RequestURI(),
							"status": statusCode,
						}).Error("monolithic proxy authz check failed")
						c.Status(statusCode)
						return
					}
					if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
						log.WithFields(log.Fields{
							"method": c.Request.Method,
							"path":   c.Request.URL.RequestURI(),
							"status": statusCode,
						}).Info("monolithic proxy authz denied request")
						c.Status(statusCode)
						return
					}
				}

				remote, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", servicePort))
				if err != nil {
					panic(err)
				}
				proxyUrl := targetSubpath + strings.TrimPrefix(c.Param("proxyPath"), subpath)
				if targetPath == "" {
					proxyUrl = strings.TrimSuffix(proxyUrl, "/")
				}
				//emulate envoy config by generating rand request id as HTTP header to the upstream service
				c.Request.Header.Add("x-request-id", uuid.NewString())
				proxy := httputil.NewSingleHostReverseProxy(remote)
				proxy.Director = func(req *http.Request) {
					req.Header = c.Request.Header
					req.Host = remote.Host
					req.URL.Scheme = remote.Scheme
					req.URL.Host = remote.Host
					req.URL.Path = proxyUrl
				}
				proxy.ModifyResponse = func(resp *http.Response) error {
					resp.Header.Del("Access-Control-Allow-Origin")
					resp.Header.Del("Access-Control-Allow-Headers")
					resp.Header.Del("Access-Control-Allow-Methods")
					resp.Header.Del("Access-Control-Allow-Credentials")
					resp.Header.Del("Access-Control-Expose-Headers")
					resp.Header.Del("Access-Control-Max-Age")
					return nil
				}
				proxy.ServeHTTP(c.Writer, c.Request)
			}
			routeList = make([]string, 0, len(routeMaps))
			for k := range routeMaps {
				routeList = append(routeList, k)
			}
		}

		addRouteMap := func(serviceName, servicePath string, servicePort int) {
			registerRoute(serviceName, servicePath, servicePort, "")
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
			proxy.ModifyResponse = func(resp *http.Response) error {
				resp.Header.Del("Access-Control-Allow-Origin")
				resp.Header.Del("Access-Control-Allow-Headers")
				resp.Header.Del("Access-Control-Allow-Methods")
				resp.Header.Del("Access-Control-Allow-Credentials")
				resp.Header.Del("Access-Control-Expose-Headers")
				resp.Header.Del("Access-Control-Max-Age")
				return nil
			}
			proxy.ServeHTTP(c.Writer, c.Request)
		}

		addRouteMap("KMS", "/api/kms/", kmsPort)
		addRouteMap("CA", "/api/ca/", caPort)
		addRouteMap("Dev Manager", "/api/devmanager/", devPort)
		addRouteMap("DMS Manager", "/api/dmsmanager/", dmsPort)
		addRouteMap("VA", "/api/va/", vaPort)
		addRouteMap("Alerts", "/api/alerts/", alertsPort)

		if conf.WfxNorthPort > 0 {
			registerRoute("wfx NBI", "/api/wfx/nbi/", conf.WfxNorthPort, "/api/wfx/")
		}
		if conf.WfxSouthPort > 0 {
			registerRoute("wfx SBI", "/api/wfx/sbi/", conf.WfxSouthPort, "/api/wfx/")
		}

		if authzPort > 0 {
			addRouteMap("Authz", "/api/authz/", authzPort)
		}

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

type monolithicAuthzProxy struct {
	port     int
	prefixes []string
	client   *http.Client
}

func newMonolithicAuthzProxy(port int, prefixes []string) *monolithicAuthzProxy {
	if port <= 0 || len(prefixes) == 0 {
		return nil
	}
	return &monolithicAuthzProxy{
		port:     port,
		prefixes: prefixes,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func authzProxyPrefixes(conf MonolithicConfig) []string {
	if conf.AuthzProxyPrefixes != nil {
		return normalizePathPrefixes(conf.AuthzProxyPrefixes)
	}
	if conf.WfxNorthPort > 0 || conf.WfxSouthPort > 0 {
		return []string{"/api/wfx/nbi/", "/api/wfx/sbi/"}
	}
	return nil
}

func normalizePathPrefixes(prefixes []string) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		out = append(out, prefix)
	}
	return out
}

func (proxy *monolithicAuthzProxy) protects(path string) bool {
	for _, prefix := range proxy.prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (proxy *monolithicAuthzProxy) authorize(req *http.Request) (int, error) {
	body, err := readAndRestoreRequestBody(req)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("read request body for authz check: %w", err)
	}

	checkURL := fmt.Sprintf("http://127.0.0.1:%d/v1/ext_authz/check%s", proxy.port, req.URL.RequestURI())
	checkReq, err := http.NewRequestWithContext(req.Context(), req.Method, checkURL, bytes.NewReader(body))
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("create authz check request: %w", err)
	}
	checkReq.Header = req.Header.Clone()
	checkReq.Header.Set("x-envoy-original-path", req.URL.RequestURI())

	resp, err := proxy.client.Do(checkReq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("call authz check endpoint: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		propagateAuthzHeaders(req.Header, resp.Header)
	}
	return resp.StatusCode, nil
}

func readAndRestoreRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	body, readErr := io.ReadAll(req.Body)
	closeErr := req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.ContentLength = int64(len(body))
	if readErr != nil {
		return body, readErr
	}
	return body, closeErr
}

func propagateAuthzHeaders(reqHeaders, authzHeaders http.Header) {
	if currentUser := authzHeaders.Get("x-current-user"); currentUser != "" {
		reqHeaders.Set("x-current-user", currentUser)
		reqHeaders.Set("x-principal-id", currentUser)
	}
}

// gatewayStripHeaders are headers that clients must not be allowed to inject —
// they are either set by this gateway or by internal services only.
var gatewayStripHeaders = []string{
	"X-Principal-Id",
	"X-Lms-Source",
	"X-Request-Id", // gateway assigns its own UUID downstream
	"X-Forwarded-Cert",
	"X-Forwarded-Client-Cert", // set by gateway after TLS inspection
	"Ssl-Client-Cert",         // nginx mTLS proxy header
	"X-Amzn-Mtls-Clientcert",  // AWS ALB mTLS header
}

func stripIncomingHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, h := range gatewayStripHeaders {
			c.Request.Header.Del(h)
		}
		c.Next()
	}
}

func clientCertsToHeaderUsingEnvoyStyle() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS != nil {
			if len(c.Request.TLS.PeerCertificates) > 0 {
				c.Request.Header.Add("x-forwarded-client-cert", envoyStyleClientCertHeader(c.Request.TLS.PeerCertificates))
			}
		}

		c.Next()
	}
}

func envoyStyleClientCertHeader(certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}

	leafURLEnc := url.QueryEscape(chelpers.CertificateToPEM(certs[0]))
	fullChain := ""
	for _, crt := range certs {
		fullChain += chelpers.CertificateToPEM(crt)
	}
	chainURLEnc := url.QueryEscape(fullChain)
	return fmt.Sprintf("Cert=%q;Chain=%q", leafURLEnc, chainURLEnc)
}
