package controllers

import (
	"encoding/base64"
	"fmt"
	"io"
	"math/big"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
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
			ctx.JSON(400, gin.H{"err": err.Error()})
			return
		}

		ocspReqBytes, err = base64.URLEncoding.DecodeString(params.OCSPRequest)
		if err != nil {
			r.logger.Errorf("could not parse and unescape url: %s", err)
			ctx.AbortWithError(400, err)
			return
		}

	case "POST":
		ocspReqBytes, err = io.ReadAll(ctx.Request.Body)
		if err != nil {
			r.logger.Errorf("could not read body: %s", err)
			ctx.AbortWithError(400, err)
			return
		}
	default:
		r.logger.Errorf("method not supported: %s", ctx.Request.Method)
		ctx.AbortWithError(400, fmt.Errorf("method not supported"))
		return
	}

	ocsp, err := ocsp.ParseRequest(ocspReqBytes)
	if err != nil {
		r.logger.Errorf("could not parse ocsp request: %s", err)
		ctx.AbortWithError(400, err)
		return
	}

	response, err := r.ocsp.Verify(ctx, ocsp)
	if err != nil {
		r.logger.Errorf("something went wrong while verifying ocsp request: %s", err)
		ctx.AbortWithError(500, err)
		return
	}

	ctx.Data(200, "application/ocsp-response", response)
}

func (r *vaHttpRoutes) CRL(ctx *gin.Context) {
	type uriParams struct {
		CASubjectKeyID string `uri:"ca-ski" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	crl, err := r.crl.GetCRL(ctx, services.GetCRLInput{
		CRLVersion:     big.NewInt(0),
		CASubjectKeyID: params.CASubjectKeyID,
	})
	if err != nil {
		r.logger.Errorf("something went wrong while getting crl list: %s", err)
		ctx.AbortWithError(500, err)
		return
	}

	ctx.Data(200, "application/pkix-crl", crl.Raw)
}

func (r *vaHttpRoutes) GetRoleByID(ctx *gin.Context) {
	type uriParams struct {
		CASubjectKeyID string `uri:"ca-ski" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	role, err := r.crl.GetVARole(ctx, services.GetVARoleInput{
		CASubjectKeyID: params.CASubjectKeyID,
	})
	if err != nil {
		r.logger.Errorf("something went wrong while getting va role: %s", err)
		ctx.AbortWithError(500, err)
		return
	}

	ctx.JSON(200, role)
}

func (r *vaHttpRoutes) UpdateRole(ctx *gin.Context) {
	type uriParams struct {
		CASubjectKeyID string `uri:"ca-ski" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.VARoleUpdate
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	role, err := r.crl.UpdateVARole(ctx, services.UpdateVARoleInput{
		CASubjectKeyID: params.CASubjectKeyID,
		CRLRole:        requestBody.VACRLRole,
	})
	if err != nil {
		r.logger.Errorf("something went wrong while updating va role: %s", err)
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, role)
}
