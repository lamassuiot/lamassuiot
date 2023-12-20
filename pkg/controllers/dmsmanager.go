package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

var dmsFiltrableFieldMap = map[string]resources.FilterFieldType{
	"id":          resources.StringFilterFieldType,
	"name":        resources.StringFilterFieldType,
	"creation_ts": resources.DateFilterFieldType,
}

type dmsManagerHttpRoutes struct {
	svc services.DMSManagerService
}

func NewDMSManagerHttpRoutes(svc services.DMSManagerService) *dmsManagerHttpRoutes {
	return &dmsManagerHttpRoutes{
		svc: svc,
	}
}

func (r *dmsManagerHttpRoutes) GetStats(ctx *gin.Context) {
	stats, err := r.svc.GetDMSStats(ctx, services.GetDMSStatsInput{})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, stats)
}

func (r *dmsManagerHttpRoutes) GetAllDMSs(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, dmsFiltrableFieldMap)

	dmss := []models.DMS{}
	nextBookmark, err := r.svc.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(dms models.DMS) {
				dmss = append(dmss, dms)
			},
		},
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, resources.GetDMSsResponse{
		IterableList: resources.IterableList[models.DMS]{
			NextBookmark: nextBookmark,
			List:         dmss,
		},
	})
}

func (r *dmsManagerHttpRoutes) GetDMSByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dms, err := r.svc.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: params.ID,
	})
	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dms)
}

func (r *dmsManagerHttpRoutes) CreateDMS(ctx *gin.Context) {
	var requestBody resources.CreateDMSBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.AbortWithStatusJSON(400, gin.H{"err": err.Error()})
		return
	}

	input := services.CreateDMSInput{
		ID:       requestBody.ID,
		Metadata: requestBody.Metadata,
		Name:     requestBody.Name,
		Settings: requestBody.Settings,
	}

	dms, err := r.svc.CreateDMS(ctx, input)

	if err != nil {
		ctx.AbortWithStatusJSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(201, dms)
}

func (r *dmsManagerHttpRoutes) UpdateDMS(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody models.DMS
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.UpdateDMS(ctx, services.UpdateDMSInput{
		DMS: requestBody,
	})
	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, ca)
}

func (r *dmsManagerHttpRoutes) BindIdentityToDevice(ctx *gin.Context) {
	var requestBody resources.BindIdentityToDeviceBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	bind, err := r.svc.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                requestBody.DeviceID,
		CertificateSerialNumber: requestBody.CertificateSerialNumber,
		BindMode:                models.DeviceEventType(requestBody.BindMode),
	})
	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, bind)
}
