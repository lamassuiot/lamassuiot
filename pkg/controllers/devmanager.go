package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type devManagerHttpRoutes struct {
	svc services.DeviceManagerService
}

func NewDeviceManagerHttpRoutes(svc services.DeviceManagerService) *devManagerHttpRoutes {
	return &devManagerHttpRoutes{
		svc: svc,
	}
}

func (r *devManagerHttpRoutes) GetAllDevices(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request)

	devices := []*models.Device{}
	nextBookmark, err := r.svc.GetDevices(services.GetDevicesInput{
		ListInput: services.ListInput[models.Device]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(dev *models.Device) {
				devices = append(devices, dev)
			},
		},
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, resources.GetDevicesResponse{
		IterbaleList: resources.IterbaleList[models.Device]{
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
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	dms, err := r.svc.GetDeviceByID(services.GetDeviceByIDInput{
		ID: params.ID,
	})
	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, dms)
}

func (r *devManagerHttpRoutes) CreateDevice(ctx *gin.Context) {
	var requestBody resources.CreateDeviceBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.CreateDevice(services.CreateDeviceInput{
		ID:                 requestBody.ID,
		Alias:              requestBody.Alias,
		Tags:               requestBody.Tags,
		Metadata:           requestBody.Metadata,
		Icon:               requestBody.Icon,
		IconColor:          requestBody.IconColor,
		ConnectionMetadata: requestBody.ConnectionMetadata,
		DMSID:              requestBody.DMSID,
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(201, dev)
}

func (r *devManagerHttpRoutes) DecommisionDevice(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	dev, err := r.svc.DecommisionDevice(services.DecommisionDeviceInput{
		ID: params.ID,
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, dev)
}
