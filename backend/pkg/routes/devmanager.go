package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewDeviceManagerHTTPLayer(router *gin.RouterGroup, svc services.DeviceManagerService, options ...TenantRouteOptions) {
	routes := controllers.NewDeviceManagerHttpRoutes(svc)
	config := tenantRouteOptions(options)
	v1, v2 := TenantAwareGroups(router, config)
	register := func(version *gin.RouterGroup) {
		deviceRead := PermissionGroup(version, "device.read", config.Authorization)
		deviceWrite := PermissionGroup(version, "device.write", config.Authorization)
		deviceDecommission := PermissionGroup(version, "device.decommission", config.Authorization)
		groupRead := PermissionGroup(version, "group.read", config.Authorization)
		groupWrite := PermissionGroup(version, "group.write", config.Authorization)

		deviceRead.GET("/stats", routes.GetStats)
		deviceRead.GET("/devices", routes.GetAllDevices)
		deviceWrite.POST("/devices", routes.CreateDevice)
		deviceRead.GET("/devices/:id", routes.GetDeviceByID)
		deviceWrite.DELETE("/devices/:id", routes.DeleteDevice)
		deviceWrite.PUT("/devices/:id/idslot", routes.UpdateDeviceIdentitySlot)
		deviceWrite.PUT("/devices/:id/metadata", routes.UpdateDeviceMetadata)
		deviceWrite.PATCH("/devices/:id/metadata", routes.UpdateDeviceMetadata)
		deviceDecommission.DELETE("/devices/:id/decommission", routes.DecommissionDevice)
		deviceRead.GET("/devices/dms/:id", routes.GetDevicesByDMS)
		groupWrite.POST("/device-groups", routes.CreateDeviceGroup)
		groupRead.GET("/device-groups", routes.GetAllDeviceGroups)
		groupRead.GET("/device-groups/:id", routes.GetDeviceGroupByID)
		groupWrite.PUT("/device-groups/:id", routes.UpdateDeviceGroup)
		groupWrite.DELETE("/device-groups/:id", routes.DeleteDeviceGroup)
		groupRead.GET("/device-groups/:id/devices", routes.GetDevicesByGroup)
		groupRead.GET("/device-groups/:id/stats", routes.GetDeviceGroupStats)
	}
	register(v1)
	register(v2)
}
