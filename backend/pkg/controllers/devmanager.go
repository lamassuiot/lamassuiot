package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
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
	queryParams, err := FilterQuery(ctx.Request, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	stats, err := r.svc.GetDevicesStats(ctx, services.GetDevicesStatsInput{
		QueryParameters: queryParams,
	})

	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(200, stats)
}

func (r *devManagerHttpRoutes) GetAllDevices(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDevices(ctx.Request.Context(), services.GetDevicesInput{
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
	queryParams, err := FilterQuery(ctx.Request, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	type uriParams struct {
		DMSID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDeviceByDMS(ctx.Request.Context(), services.GetDevicesByDMSInput{
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

	dms, err := r.svc.GetDeviceByID(ctx.Request.Context(), services.GetDeviceByIDInput{
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

	dev, err := r.svc.CreateDevice(ctx.Request.Context(), services.CreateDeviceInput{
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

	dev, err := r.svc.UpdateDeviceIdentitySlot(ctx.Request.Context(), services.UpdateDeviceIdentitySlotInput{
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

	dev, err := r.svc.UpdateDeviceMetadata(ctx.Request.Context(), services.UpdateDeviceMetadataInput{
		ID:      params.ID,
		Patches: requestBody.Patches,
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

	dev, err := r.svc.UpdateDeviceStatus(ctx.Request.Context(), services.UpdateDeviceStatusInput{
		ID:        params.ID,
		NewStatus: models.DeviceDecommissioned,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dev)
}

func (r *devManagerHttpRoutes) DeleteDevice(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	err := r.svc.DeleteDevice(ctx.Request.Context(), services.DeleteDeviceInput{
		ID: params.ID,
	})

	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrDeviceInvalidStatus:
			ctx.JSON(422, gin.H{"err": err.Error()}) // Unprocessable Entity for invalid state
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.Status(204) // No Content for successful deletion
}
