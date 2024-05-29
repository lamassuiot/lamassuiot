package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type devManagerHttpRoutes struct {
	svc services.DeviceManagerService
}

func NewDeviceManagerHttpRoutes(svc services.DeviceManagerService) *devManagerHttpRoutes {
	return &devManagerHttpRoutes{
		svc: svc,
	}
}

func (r *devManagerHttpRoutes) GetStats(ctx *gin.Context) {
	stats, err := r.svc.GetDevicesStats(ctx, services.GetDevicesStatsInput{})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, stats)
}

func (r *devManagerHttpRoutes) GetAllDevices(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, resources.DeviceFiltrableFields)

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDevices(ctx, services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, resources.GetDevicesResponse{
		IterableList: resources.IterableList[models.Device]{
			NextBookmark: nextBookmark,
			List:         devices,
		},
	})
}

func (r *devManagerHttpRoutes) GetDevicesByDMS(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, resources.DeviceFiltrableFields)
	type uriParams struct {
		DMSID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDeviceByDMS(ctx, services.GetDevicesByDMSInput{
		DMSID: params.DMSID,
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, resources.GetDevicesResponse{
		IterableList: resources.IterableList[models.Device]{
			NextBookmark: nextBookmark,
			List:         devices,
		},
	})
}

func (r *devManagerHttpRoutes) GetDeviceByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dms, err := r.svc.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: params.ID,
	})
	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			ctx.JSON(400, gin.H{"err": err.Error()})
			return
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
			return
		}
	}

	ctx.JSON(200, dms)
}

func (r *devManagerHttpRoutes) CreateDevice(ctx *gin.Context) {
	var requestBody resources.CreateDeviceBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        requestBody.ID,
		Alias:     requestBody.Alias,
		Tags:      requestBody.Tags,
		Metadata:  requestBody.Metadata,
		Icon:      requestBody.Icon,
		IconColor: requestBody.IconColor,
		DMSID:     requestBody.DMSID,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(201, dev)
}

func (r *devManagerHttpRoutes) UpdateDeviceIdentitySlot(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateDeviceIdentitySlotBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
		ID:   params.ID,
		Slot: requestBody.Slot,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dev)
}

func (r *devManagerHttpRoutes) UpdateDeviceMetadata(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateDeviceMetadataBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID:       params.ID,
		Metadata: requestBody.Metadata,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dev)
}

func (r *devManagerHttpRoutes) DecommissionDevice(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
		ID:        params.ID,
		NewStatus: models.DeviceDecommissioned,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dev)
}
