package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

type dmsManagerHttpRoutes struct {
	svc services.DMSManagerService
}

func NewDMSManagerHttpRoutes(svc services.DMSManagerService) *dmsManagerHttpRoutes {
	return &dmsManagerHttpRoutes{
		svc: svc,
	}
}

func (r *dmsManagerHttpRoutes) GetAllDMSs(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request)

	dmss := []*models.DMS{}
	nextBookmark, err := r.svc.GetAll(services.GetAllInput{
		ListInput: services.ListInput[models.DMS]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(cert *models.DMS) {
				dmss = append(dmss, cert)
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
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	dms, err := r.svc.GetDMSByID(services.GetDMSByIDInput{
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
		ID:              requestBody.ID,
		Metadata:        requestBody.Metadata,
		Name:            requestBody.Name,
		IdentityProfile: requestBody.IdentityProfile,
	}

	dms, err := r.svc.CreateDMS(input)

	if err != nil {
		ctx.AbortWithStatusJSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(201, dms)
}

func (r *dmsManagerHttpRoutes) UpdateIdentityProfile(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	var requestBody models.IdentityProfile
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.UpdateIdentityProfile(services.UpdateIdentityProfileInput{
		ID:                 params.ID,
		NewIdentityProfile: requestBody,
	})
	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, ca)
}
