package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
)

type hcheckRoute struct {
	info models.APIServiceInfo
}

func NewHealthCheckRoute(info models.APIServiceInfo) *hcheckRoute {
	return &hcheckRoute{
		info: info,
	}
}

func (r *hcheckRoute) HealthCheck(ctx *gin.Context) {
	ctx.JSON(200, gin.H{
		"health":     true,
		"version":    r.info.Version,
		"build":      r.info.BuildSHA,
		"build_time": r.info.BuildTime,
	})
}
