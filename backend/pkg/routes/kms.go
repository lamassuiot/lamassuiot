package routes

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	authzschemas "github.com/lamassuiot/authz"
	authzcore "github.com/lamassuiot/authz/pkg/core"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewKMSHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.KMSService, authzConf config.AuthzClient, logger *logrus.Entry) {
	newKMSHTTPLayer(parentRouterGroup, svc, authzConf, logger)
}

func newKMSHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.KMSService, authzConf config.AuthzClient, logger *logrus.Entry) *middleware.ContractRouter {
	return registerKMSRoutes(parentRouterGroup, svc, newRemoteAuthzEngine(authzConf, models.KMSSource, logger), logger)
}

// Production and tests share the URI/alias resolver and route declarations.
func registerKMSRoutes(parentRouterGroup *gin.RouterGroup, svc services.KMSService, engine authzcore.AuthzEngine, logger *logrus.Entry) *middleware.ContractRouter {
	routes := controllers.NewKMSHttpRoutes(svc)

	// A key is identified by (key_id, engine_id), so the authz entity key can only be built
	// from a PKCS#11 URI, which carries the engine in token-id, or from an alias, which is
	// unique across engines but needs a storage lookup to resolve. Same rule as svc.GetKey;
	// it lives in both places because the authz middleware is bypassed in admin mode.
	keyIDExtractor := func(c *gin.Context) map[string]string {
		identifier := c.Param("id")

		if strings.HasPrefix(identifier, "pkcs11:") {
			keyUriParts, err := models.ParsePKCS11URI(identifier)
			if err != nil || keyUriParts["id"] == "" || keyUriParts["token-id"] == "" {
				c.AbortWithStatusJSON(400, gin.H{"err": errs.ErrValidateBadRequest.Error()})
				return nil
			}

			return map[string]string{
				"key_id":    keyUriParts["id"],
				"engine_id": keyUriParts["token-id"],
			}
		}

		// Resolving an alias reads storage before the caller is known to be authorized, so
		// every failure denies with the same status: distinguishing "no such key" from
		// "held by several engines" here would tell an unauthorized caller which
		// identifiers exist and which are mirrored.
		key, err := svc.GetKey(c.Request.Context(), services.GetKeyInput{Identifier: identifier})
		if err != nil {
			c.AbortWithStatusJSON(403, gin.H{"err": "Access denied"})
			return nil
		}

		return map[string]string{
			"key_id":    key.KeyID,
			"engine_id": key.EngineID,
		}
	}

	schemas, err := authzschemas.PKISchemas()
	if err != nil {
		panic(err)
	}
	kmsAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "kms", "kms_key", logger)

	router := parentRouterGroup
	rv1 := router.Group("/v1")
	contract := middleware.NewContractRouter(rv1)

	contract.Handle(http.MethodGet, "/stats", kmsAuthzMw.List(), routes.GetStats)
	contract.Handle(http.MethodGet, "/engines", kmsAuthzMw.List(), routes.GetCryptoEngineProvider)

	contract.Handle(http.MethodGet, "/keys", kmsAuthzMw.List(), routes.GetKeys)
	contract.Handle(http.MethodGet, "/keys/:id", kmsAuthzMw.ResourceCustom("read", "id", keyIDExtractor), routes.GetKeyByID)
	contract.Handle(http.MethodPost, "/keys", kmsAuthzMw.Global("create"), routes.CreateKey)
	contract.Handle(http.MethodPost, "/keys/import", kmsAuthzMw.Global("create"), routes.ImportKey)
	contract.Handle(http.MethodPut, "/keys/:id/alias", kmsAuthzMw.ResourceCustom("update", "id", keyIDExtractor), routes.UpdateKeyAliases)
	contract.Handle(http.MethodPut, "/keys/:id/name", kmsAuthzMw.ResourceCustom("update", "id", keyIDExtractor), routes.UpdateKeyName)
	contract.Handle(http.MethodPut, "/keys/:id/tags", kmsAuthzMw.ResourceCustom("update", "id", keyIDExtractor), routes.UpdateKeyTags)
	contract.Handle(http.MethodPut, "/keys/:id/metadata", kmsAuthzMw.ResourceCustom("update", "id", keyIDExtractor), routes.UpdateKeyMetadata)
	contract.Handle(http.MethodDelete, "/keys/:id", kmsAuthzMw.ResourceCustom("delete", "id", keyIDExtractor), routes.DeleteKeyByID)
	contract.Handle(http.MethodPost, "/keys/:id/sign", kmsAuthzMw.ResourceCustom("sign", "id", keyIDExtractor), routes.SignMessage)
	contract.Handle(http.MethodPost, "/keys/:id/verify", kmsAuthzMw.ResourceCustom("read", "id", keyIDExtractor), routes.VerifySignature)
	return contract
}
