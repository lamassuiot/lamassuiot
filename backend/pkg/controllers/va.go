package controllers

import (
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type VAHttpRoutes interface {
	Verify(ctx *gin.Context)
	CRL(ctx *gin.Context)
}

type backendVAHttpRoutes struct {
	ocsp   services.OCSPService
	crl    services.CRLService
	logger *logrus.Entry
}

func NewBackendVAHttpRoutes(logger *logrus.Entry, ocsp services.OCSPService, crl services.CRLService) VAHttpRoutes {
	return &backendVAHttpRoutes{
		ocsp:   ocsp,
		crl:    crl,
		logger: logger,
	}
}

func (r *backendVAHttpRoutes) Verify(ctx *gin.Context) {
	if ctx.Request.Header.Get("Content-Type") != "application/ocsp-request" {
		r.logger.Warnf("request did not include 'application/ocsp-request' as the content-type")
	}

	var ocspReqString string
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

		base64Request, err := url.QueryUnescape(params.OCSPRequest)
		if err != nil {
			r.logger.Errorf("could not parse and unescape url: %s", err)
			ctx.AbortWithError(400, err)
			return
		}
		// url.QueryUnescape not only unescapes %2B escaping, but it additionally
		// turns the resulting '+' into a space, which makes base64 decoding fail.
		// So we go back afterwards and turn ' ' back into '+'. This means we
		// accept some malformed input that includes ' ' or %20, but that's fine.
		base64RequestBytes := []byte(base64Request)
		for i := range base64RequestBytes {
			if base64RequestBytes[i] == ' ' {
				base64RequestBytes[i] = '+'
			}
		}
		// In certain situations a UA may construct a request that has a double
		// slash between the host name and the base64 request body due to naively
		// constructing the request URL. In that case strip the leading slash
		// so that we can still decode the request.
		if len(base64RequestBytes) > 0 && base64RequestBytes[0] == '/' {
			base64RequestBytes = base64RequestBytes[1:]
		}

		ocspReqBytes, err := base64.StdEncoding.DecodeString(string(base64RequestBytes))
		if err != nil {
			r.logger.Errorf("could not decode b64 ocsp request: %s", err)
			ctx.AbortWithError(400, err)
			return
		}

		ocspReqString = string(ocspReqBytes)
	case "POST":
		ocspReqBytes, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			r.logger.Errorf("could not read body: %s", err)
			ctx.AbortWithError(400, err)
			return
		}
		ocspReqString = string(ocspReqBytes)
	default:
		r.logger.Errorf("method not supported: %s", ctx.Request.Method)
		ctx.AbortWithError(400, fmt.Errorf("method not supported"))
		return
	}

	ocsp, err := ocsp.ParseRequest([]byte(ocspReqString))
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

func (r *backendVAHttpRoutes) CRL(ctx *gin.Context) {
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

func (r *vaHttpRoutes) GetRoles(ctx *gin.Context) {
	roles := []models.VARole{}
	queryParams := FilterQuery(ctx.Request, map[string]resources.FilterFieldType{})

	nBMark, err := r.crl.GetVARoles(ctx, services.GetVARolesInput{
		QueryParameters: queryParams,
		ExhaustiveRun:   false,
		ApplyFunc: func(v models.VARole) {
			roles = append(roles, v)
		},
	})
	if err != nil {
		r.logger.Errorf("something went wrong while getting va roles list: %s", err)
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.IterableList[models.VARole]{
		NextBookmark: nBMark,
		List:         roles,
	})
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
