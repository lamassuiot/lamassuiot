package controllers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type vaHttpRoutes struct {
	ocsp   services.OCSPService
	crl    services.CRLService
	logger *logrus.Entry
}

func NewVAHttpRoutes(logger *logrus.Entry, ocsp services.OCSPService, crl services.CRLService) *vaHttpRoutes {
	return &vaHttpRoutes{
		ocsp:   ocsp,
		crl:    crl,
		logger: logger,
	}
}

func (r *vaHttpRoutes) handleError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, errs.ErrCRLSettingsNotFound), errors.Is(err, errs.ErrCRLNotFound), errors.Is(err, errs.ErrCANotFound), errors.Is(err, errs.ErrCertificateNotFound):
		ctx.JSON(http.StatusNotFound, gin.H{"err": err.Error()})
	case errors.Is(err, errs.ErrCRLSettingsNotActive):
		ctx.JSON(http.StatusConflict, gin.H{"err": err.Error()})
	case errors.Is(err, errs.ErrValidateBadRequest):
		ctx.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
	default:
		ctx.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
	}
}

func (r *vaHttpRoutes) Verify(ctx *gin.Context) {
	if ctx.Request.Header.Get("Content-Type") != "application/ocsp-request" {
		r.logger.Warnf("request did not include 'application/ocsp-request' as the content-type")
	}

	var ocspReqBytes []byte
	var err error
	switch ctx.Request.Method {
	case "GET":
		type uriParams struct {
			OCSPRequest string `uri:"ocsp_request" binding:"required"`
		}

		var params uriParams
		if err := ctx.ShouldBindUri(&params); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
			return
		}

		ocspReqBytes, err = base64.URLEncoding.DecodeString(params.OCSPRequest)
		if err != nil {
			r.logger.Errorf("could not parse and unescape url: %s", err)
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}

	case "POST":
		ocspReqBytes, err = io.ReadAll(ctx.Request.Body)
		if err != nil {
			r.logger.Errorf("could not read body: %s", err)
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}
	default:
		r.logger.Errorf("method not supported: %s", ctx.Request.Method)
		ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("method not supported"))
		return
	}

	ocsp, err := ocsp.ParseRequest(ocspReqBytes)
	if err != nil {
		r.logger.Errorf("could not parse ocsp request: %s", err)
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	response, err := r.ocsp.Verify(ctx.Request.Context(), ocsp)
	if err != nil {
		r.logger.Errorf("something went wrong while verifying ocsp request: %s", err)
		ctx.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	ctx.Data(http.StatusOK, "application/ocsp-response", response)
}

func (r *vaHttpRoutes) CRL(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
		return
	}

	crl, err := r.crl.GetCRL(ctx.Request.Context(), services.GetCRLInput{
		CRLVersion: big.NewInt(0),
		ID:         params.ID,
	})
	if err != nil {
		r.logger.Errorf("something went wrong while getting crl list: %s", err)
		r.handleError(ctx, err)
		return
	}

	ctx.Data(http.StatusOK, "application/pkix-crl", crl.Raw)
}

func (r *vaHttpRoutes) GetCRLSettingsList(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.CRLSettingsFilterableFields)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
		return
	}

	items := []models.CRLSettings{}
	nextBookmark, err := r.crl.GetCRLSettingsList(ctx.Request.Context(), services.GetCRLSettingsListInput{
		QueryParameters: queryParams,
		ExhaustiveRun:   false,
		ApplyFunc: func(item models.CRLSettings) {
			items = append(items, item)
		},
	})
	if err != nil {
		r.logger.Errorf("something went wrong while listing crl settings: %s", err)
		r.handleError(ctx, err)
		return
	}

	ctx.JSON(http.StatusOK, resources.GetItemsResponse[models.CRLSettings]{
		NextBookmark: nextBookmark,
		List:         items,
	})
}

func (r *vaHttpRoutes) GetCRLSettingsByID(ctx *gin.Context) {
	type uriParams struct {
		CAID string `uri:"ca-id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
		return
	}

	settings, err := r.crl.GetCRLSettings(ctx.Request.Context(), services.GetCRLSettingsInput{
		CAID: params.CAID,
	})
	if err != nil {
		r.logger.Errorf("something went wrong while getting crl settings: %s", err)
		r.handleError(ctx, err)
		return
	}

	ctx.JSON(http.StatusOK, settings)
}

func (r *vaHttpRoutes) UpdateCRLSettings(ctx *gin.Context) {
	type uriParams struct {
		CAID string `uri:"ca-id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.CRLSettingsUpdate
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
		return
	}

	settings, err := r.crl.UpdateCRLSettings(ctx.Request.Context(), services.UpdateCRLSettingsInput{
		CAID:    params.CAID,
		Options: requestBody.CRLSettingsOptions,
	})
	if err != nil {
		r.logger.Errorf("something went wrong while updating crl settings: %s", err)
		r.handleError(ctx, err)
		return
	}

	ctx.JSON(http.StatusOK, settings)
}
