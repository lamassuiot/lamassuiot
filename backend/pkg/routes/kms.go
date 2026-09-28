package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewKMSHTTPLayer(logger *logrus.Entry, parentRouterGroup *gin.RouterGroup, svc services.KMSService, options ...TenantRouteOptions) {
	routes := controllers.NewKMSHttpRoutes(logger, svc)
	config := tenantRouteOptions(options)
	v1, v2 := TenantAwareGroups(parentRouterGroup, config)
	register := func(router *gin.RouterGroup) {
		kmsRead := PermissionGroup(router, "kms.read", config.Authorization)
		keyRead := PermissionGroup(router, "key.read", config.Authorization)
		keyManage := PermissionGroup(router, "key.manage", config.Authorization)
		keyImport := PermissionGroup(router, "key.import", config.Authorization)
		keySign := PermissionGroup(router, "key.sign", config.Authorization)
		keyVerify := PermissionGroup(router, "key.verify", config.Authorization)

		kmsRead.GET("/stats", routes.GetStats)
		kmsRead.GET("/engines", routes.GetCryptoEngineProvider)
		keyRead.GET("/keys", routes.GetKeys)
		keyRead.GET("/keys/:id", routes.GetKeyByID)
		keyManage.POST("/keys", routes.CreateKey)
		keyImport.POST("/keys/import", routes.ImportKey)
		keyManage.PUT("/keys/:id/alias", routes.UpdateKeyAliases)
		keyManage.PUT("/keys/:id/name", routes.UpdateKeyName)
		keyManage.PUT("/keys/:id/tags", routes.UpdateKeyTags)
		keyManage.PUT("/keys/:id/metadata", routes.UpdateKeyMetadata)
		keyManage.DELETE("/keys/:id", routes.DeleteKeyByID)
		keySign.POST("/keys/:id/sign", routes.SignMessage)
		keyVerify.POST("/keys/:id/verify", routes.VerifySignature)
	}
	register(v1)
	register(v2)
}
