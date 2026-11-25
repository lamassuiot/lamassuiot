package routes

import (
	"context"
	"fmt"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	authzschemas "github.com/lamassuiot/lamassuiot/v4/connectors/authz"
	authzcore "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/core"
	authzSdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	middleware "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
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

// authzSchemas are the entities of authz itself, for permissions such as granting a policy.
var authzSchemas = sync.OnceValues(authzschemas.AuthzSchemas)

// policyGrantCheck is the permission to grant authz policies, which the DMS Manager asks for only when a save
// of an RA needs it. It is declared with the route so the contract and the OpenAPI list it.
func policyGrantCheck(engine authzcore.AuthzEngine, logger *logrus.Entry) middleware.ServiceCheck {
	schemas, err := authzSchemas()
	if err != nil {
		panic(err)
	}
	return middleware.MustNewAuthzMiddleware(engine, schemas, "authz", "public", "principal_policy", logger).GlobalCheck("grant")
}

// withPolicyGrantCheck puts the check, bound to the caller of the request, in the context of the service.
func withPolicyGrantCheck(permission middleware.Permission, check middleware.ServiceCheck) middleware.Permission {
	return permission.WithServiceCheck(check, func(c *gin.Context, allowed func(context.Context) (bool, error)) {
		c.Request = c.Request.WithContext(services.WithPolicyGrantCheck(c.Request.Context(), allowed))
	})
}

// pkiAuthz builds a middleware for a "pki" entity, rejecting unknown entities at startup.
func pkiAuthz(engine authzcore.AuthzEngine, schemaName, entityType string, logger *logrus.Entry) *middleware.AuthzMiddleware {
	schemas, err := pkiSchemas()
	if err != nil {
		panic(err)
	}
	return middleware.MustNewAuthzMiddleware(engine, schemas, "pki", schemaName, entityType, logger)
}
