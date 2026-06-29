package routes

import (
	"github.com/gin-gonic/gin"
	middleware "github.com/lamassuiot/lamassuiot/connectors/authz/v3/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/pki/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/pki/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewKMSHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.KMSService, authzConf config.AuthzClient, logger *logrus.Entry) {
	routes := controllers.NewKMSHttpRoutes(svc)

	remoteEngine := newRemoteAuthzEngine(authzConf, models.KMSSource, logger)

	keyIDExtractor := func(c *gin.Context) map[string]string {
		pkcs11Uri := c.Param("id")
		keyUriParts, err := models.ParsePKCS11URI(pkcs11Uri)
		if err != nil {
			return map[string]string{
				"key_id": pkcs11Uri, // Fallback to using the raw ID if parsing fails
			}
		}

		keyID := keyUriParts["id"]
		engineID := keyUriParts["token-id"]
		return map[string]string{
			"key_id":    keyID,
			"engine_id": engineID,
		}
	}

	kmsAuthzMw := middleware.NewCompositeAuthzMiddleware(remoteEngine, "pki", "kms", "kms_key", []string{"key_id", "type", "engine_id"}, logger)

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
