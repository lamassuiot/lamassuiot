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
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, resources.GetDMSsResponse{
		IterbaleList: resources.IterbaleList[models.DMS]{
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
		ctx.JSON(500, gin.H{"err": err.Error()})
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
		CloudDMS: requestBody.CloudDMS,
		Metadata: requestBody.Metadata,
		Tags:     requestBody.Tags,
		Name:     requestBody.Name,
		IdentityProfile: models.IdentityProfile{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: requestBody.IdentityProfile.EnrollmentSettings.EnrollmentProtocol,
				EnrollOptions:      requestBody.IdentityProfile.EnrollmentSettings.EnrollOptions,
				DeviceProvisionSettings: models.DeviceProvisionSettings{
					Icon:       requestBody.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Icon,
					IconColor:  requestBody.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.IconColor,
					Metadata:   requestBody.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Metadata,
					Tags:       requestBody.IdentityProfile.EnrollmentSettings.DeviceProvisionSettings.Tags,
					ExtraSlots: map[string]models.SlotProfile{},
				},
				AuthorizedCA: requestBody.IdentityProfile.EnrollmentSettings.AuthorizedCA,
			},
			ReEnrollmentSettings:   requestBody.IdentityProfile.ReEnrollmentSettings,
			CADistributionSettings: requestBody.IdentityProfile.CADistributionSettings,
		},
	}

	if requestBody.RemoteAccessIdentity != nil {
		input.RemoteAccessIdentity = &services.RemoteAccessIdentityInput{
			Csr:     requestBody.RemoteAccessIdentity.CertificateRequest,
			Subject: requestBody.RemoteAccessIdentity.Subject,
		}
	}
	ca, key, err := r.svc.CreateDMS(input)

	if err != nil {
		ctx.AbortWithStatusJSON(500, gin.H{"err": err.Error()})
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

	var requestBody resources.UpdateDMSStatusBody
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
