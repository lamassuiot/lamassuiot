package routes

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/sdk"
	authzSdk "github.com/lamassuiot/authz/sdk"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
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

	remoteEngine := authzSdk.NewRemoteEngine(client)
	kmsAuthzMw := middleware.NewAuthzMiddleware(remoteEngine, "pki", "kms", "kms_key", logger)

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	rv1.GET("/stats", kmsAuthzMw.AuthListCheck(), routes.GetStats)
	rv1.GET("/engines", kmsAuthzMw.AuthListCheck(), routes.GetCryptoEngineProvider)

	rv1.GET("/keys", kmsAuthzMw.AuthListCheck(), routes.GetKeys)
	rv1.GET("/keys/:id", kmsAuthzMw.AuthzCheck("read"), routes.GetKeyByID)
	rv1.POST("/keys", kmsAuthzMw.AuthzCheck("create"), routes.CreateKey)
	rv1.POST("/keys/import", kmsAuthzMw.AuthzCheck("create"), routes.ImportKey)
	rv1.PUT("/keys/:id/alias", kmsAuthzMw.AuthzCheck("update"), routes.UpdateKeyAliases)
	rv1.PUT("/keys/:id/name", kmsAuthzMw.AuthzCheck("update"), routes.UpdateKeyName)
	rv1.PUT("/keys/:id/tags", kmsAuthzMw.AuthzCheck("update"), routes.UpdateKeyTags)
	rv1.PUT("/keys/:id/metadata", kmsAuthzMw.AuthzCheck("update"), routes.UpdateKeyMetadata)
	rv1.DELETE("/keys/:id", kmsAuthzMw.AuthzCheck("delete"), routes.DeleteKeyByID)
	rv1.POST("/keys/:id/sign", kmsAuthzMw.AuthzCheck("sign"), routes.SignMessage)
	rv1.POST("/keys/:id/verify", kmsAuthzMw.AuthzCheck("read"), routes.VerifySignature)
}
