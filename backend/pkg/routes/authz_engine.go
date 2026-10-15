package routes

import (
	"fmt"
	"sync"

	authzschemas "github.com/lamassuiot/lamassuiot/v4/connectors/authz"
	authzcore "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/core"
	authzSdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	middleware "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/sirupsen/logrus"
)

// newRemoteAuthzEngine constructs an authz RemoteEngine from the given client config.
// Fatals on startup if the SDK client cannot be created.
func newRemoteAuthzEngine(authzConf config.AuthzClient, source string, logger *logrus.Entry) authzcore.AuthzEngine {
	sdkCfg := authzSdk.DefaultConfig(
		fmt.Sprintf("%s://%s:%d%s", authzConf.Protocol, authzConf.Hostname, authzConf.Port, authzConf.BasePath),
		source,
	)
	sdkCfg.InsecureSkipVerify = authzConf.InsecureSkipVerify
	client, err := authzSdk.NewClient(sdkCfg)
	if err != nil {
		logger.Fatalf("Failed to create authz SDK client: %v", err)
		return nil // unreachable; Fatalf exits
	}
	return authzSdk.NewRemoteEngine(client)
}

// The embedded PKI schemas are parsed once and shared by every service layer.
var pkiSchemas = sync.OnceValues(authzschemas.PKISchemas)

// pkiAuthz builds a middleware for a "pki" entity, rejecting unknown entities at startup.
func pkiAuthz(engine authzcore.AuthzEngine, schemaName, entityType string, logger *logrus.Entry) *middleware.AuthzMiddleware {
	schemas, err := pkiSchemas()
	if err != nil {
		panic(err)
	}
	return middleware.MustNewAuthzMiddleware(engine, schemas, "pki", schemaName, entityType, logger)
}
