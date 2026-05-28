package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewDMSManagerHTTPLayer(logger *logrus.Entry, httpGrp *gin.RouterGroup, svc services.DMSManagerService) error {
	routes := controllers.NewDMSManagerHttpRoutes(svc)

	NewESTHttpRoutes(logger, httpGrp, svc)
	if err := NewCMPHTTPLayer(logger, httpGrp, svc); err != nil {
		return err
	}

	rv1 := httpGrp.Group("/v1")

	rv1.GET("/stats", routes.GetStats)
	rv1.GET("/dms", routes.GetAllDMSs)
	rv1.POST("/dms", routes.CreateDMS)
	rv1.GET("/dms/:id", routes.GetDMSByID)
	rv1.PUT("/dms/:id", routes.UpdateDMS)
	rv1.PUT("/dms/:id/metadata", routes.UpdateDMSMetadata)
	rv1.PATCH("/dms/:id/metadata", routes.UpdateDMSMetadata)
	rv1.DELETE("/dms/:id", routes.DeleteDMS)
	rv1.POST("/dms/bind-identity", routes.BindIdentityToDevice)
	rv1.GET("/dms/:id/cmp/transactions", routes.GetCMPTransactionsByDMS)
	rv1.POST("/dms/:id/cmp/transactions/:txid/approve", routes.ApproveCMPTransaction)
	rv1.POST("/dms/:id/cmp/transactions/:txid/reject", routes.RejectCMPTransaction)

	return nil
}
