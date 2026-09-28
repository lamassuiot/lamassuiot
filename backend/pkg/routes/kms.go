package routes

import (
	"strings"

	"github.com/gin-gonic/gin"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewKMSHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.KMSService, authzConf config.AuthzClient, logger *logrus.Entry) {
	routes := controllers.NewKMSHttpRoutes(svc)

	remoteEngine := newRemoteAuthzEngine(authzConf, models.KMSSource, logger)

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

	kmsAuthzMw := middleware.NewCompositeAuthzMiddleware(remoteEngine, "pki", "kms", "kms_key", []string{"key_id", "engine_id"}, logger)

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	rv1.GET("/stats", kmsAuthzMw.AuthListCheck(), routes.GetStats)
	rv1.GET("/engines", kmsAuthzMw.AuthListCheck(), routes.GetCryptoEngineProvider)

	rv1.GET("/keys", kmsAuthzMw.AuthListCheck(), routes.GetKeys)
	rv1.GET("/keys/:id", kmsAuthzMw.AuthzCheckCustom("read", keyIDExtractor), routes.GetKeyByID)
	rv1.POST("/keys", kmsAuthzMw.AuthzCheck("create"), routes.CreateKey)
	rv1.POST("/keys/import", kmsAuthzMw.AuthzCheck("create"), routes.ImportKey)
	rv1.PUT("/keys/:id/alias", kmsAuthzMw.AuthzCheckCustom("update", keyIDExtractor), routes.UpdateKeyAliases)
	rv1.PUT("/keys/:id/name", kmsAuthzMw.AuthzCheckCustom("update", keyIDExtractor), routes.UpdateKeyName)
	rv1.PUT("/keys/:id/tags", kmsAuthzMw.AuthzCheckCustom("update", keyIDExtractor), routes.UpdateKeyTags)
	rv1.PUT("/keys/:id/metadata", kmsAuthzMw.AuthzCheckCustom("update", keyIDExtractor), routes.UpdateKeyMetadata)
	rv1.DELETE("/keys/:id", kmsAuthzMw.AuthzCheckCustom("delete", keyIDExtractor), routes.DeleteKeyByID)
	rv1.POST("/keys/:id/sign", kmsAuthzMw.AuthzCheckCustom("sign", keyIDExtractor), routes.SignMessage)
	rv1.POST("/keys/:id/verify", kmsAuthzMw.AuthzCheckCustom("read", keyIDExtractor), routes.VerifySignature)
}
