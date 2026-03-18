package routes

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/sdk"
	authzSdk "github.com/lamassuiot/authz/sdk"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewKMSHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.KMSService, logger *logrus.Entry) {
	routes := controllers.NewKMSHttpRoutes(svc)

	config := sdk.DefaultConfig("http://localhost:8888")
	client, err := sdk.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create SDK client: %v", err)
	}

	keyIDExractor := func(c *gin.Context) map[string]string {
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

	remoteEngine := authzSdk.NewRemoteEngine(client)
	kmsAuthzMw := middleware.NewCompositeAuthzMiddleware(remoteEngine, "pki", "kms", "kms_key", []string{"key_id", "type", "engine_id"}, logger)

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	rv1.GET("/stats", kmsAuthzMw.AuthListCheck(), routes.GetStats)
	rv1.GET("/engines", kmsAuthzMw.AuthListCheck(), routes.GetCryptoEngineProvider)

	rv1.GET("/keys", kmsAuthzMw.AuthListCheck(), routes.GetKeys)
	rv1.GET("/keys/:id", kmsAuthzMw.AuthzCheckCustom("read", keyIDExractor), routes.GetKeyByID)
	rv1.POST("/keys", kmsAuthzMw.AuthzCheckCustom("create", keyIDExractor), routes.CreateKey)
	rv1.POST("/keys/import", kmsAuthzMw.AuthzCheck("create"), routes.ImportKey)
	rv1.PUT("/keys/:id/alias", kmsAuthzMw.AuthzCheckCustom("update", keyIDExractor), routes.UpdateKeyAliases)
	rv1.PUT("/keys/:id/name", kmsAuthzMw.AuthzCheckCustom("update", keyIDExractor), routes.UpdateKeyName)
	rv1.PUT("/keys/:id/tags", kmsAuthzMw.AuthzCheckCustom("update", keyIDExractor), routes.UpdateKeyTags)
	rv1.PUT("/keys/:id/metadata", kmsAuthzMw.AuthzCheckCustom("update", keyIDExractor), routes.UpdateKeyMetadata)
	rv1.DELETE("/keys/:id", kmsAuthzMw.AuthzCheckCustom("delete", keyIDExractor), routes.DeleteKeyByID)
	rv1.POST("/keys/:id/sign", kmsAuthzMw.AuthzCheckCustom("sign", keyIDExractor), routes.SignMessage)
	rv1.POST("/keys/:id/verify", kmsAuthzMw.AuthzCheckCustom("read", keyIDExractor), routes.VerifySignature)
}
