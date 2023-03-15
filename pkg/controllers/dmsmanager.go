package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type dmsManagerHttpRoutes struct {
	svc services.DMSManagerService
}

func NewDMSManagerdmsManagerHttpRoutes(svc services.DMSManagerService) *dmsManagerHttpRoutes {
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
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, resources.GetDMSsResponse{
		NextBookmark: nextBookmark,
		DMSs:         dmss,
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
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, dms)
}

func (r *dmsManagerHttpRoutes) CreateDMS(ctx *gin.Context) {
	var requestBody resources.CreateBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, key, err := r.svc.Create(services.CreateInput{
		CloudDMS: requestBody.CloudDMS,
		Metadata: requestBody.Metadata,
		Tags:     requestBody.Tags,
		RemoteAccessIdentity: &services.RemoteAccessIdentity{
			Csr:     requestBody.RemoteAccessIdentityRequest.CertificateRequest,
			Subject: requestBody.RemoteAccessIdentityRequest.Subject,
		},
		Name: requestBody.Name,
	})

	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, &resources.CreateDMSResponse{
		PrivateKey: key,
		DMS:        ca,
	})
}

func (r *dmsManagerHttpRoutes) UpdateStatus(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	var requestBody resources.UpdateStatusBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.UpdateStatus(services.UpdateStatusInput{
		DMSID:     params.ID,
		NewStatus: requestBody.Status,
	})
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, ca)
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
		DMSID:              params.ID,
		NewIdentityProfile: requestBody,
	})
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, ca)
}
