package controllers

import (
	"crypto/x509"
	"encoding/hex"
	"math/big"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type dmsManagerHttpRoutes struct {
	svc services.DMSManagerService
}

type uriDMSIDParam struct {
	ID string `uri:"id" binding:"required"`
}

func NewDMSManagerHttpRoutes(svc services.DMSManagerService) *dmsManagerHttpRoutes {
	return &dmsManagerHttpRoutes{
		svc: svc,
	}
}

func (r *dmsManagerHttpRoutes) GetStats(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.DMSFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	stats, err := r.svc.GetDMSStats(ctx.Request.Context(), services.GetDMSStatsInput{
		QueryParameters: queryParams,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, stats)
}

func (r *dmsManagerHttpRoutes) GetAllDMSs(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.DMSFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dmss := []models.DMS{}
	nextBookmark, err := r.svc.GetAll(ctx.Request.Context(), services.GetAllInput{
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

	var params uriDMSIDParam
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dms, err := r.svc.GetDMSByID(ctx.Request.Context(), services.GetDMSByIDInput{
		ID: params.ID,
	})
	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dms)
}

// GetCMPTransactionsByDMS lists the CMP transactions associated with a DMS.
// The endpoint follows the standard list contract (page_size, bookmark,
// sort_by, filter) and projects the storage-layer row into a slim wire DTO
// that omits the raw cert/CSR DER blobs — clients fetch the certificate
// separately via /api/ca/v1/certificates/:sn when they need the body.
func (r *dmsManagerHttpRoutes) GetCMPTransactionsByDMS(ctx *gin.Context) {
	var params uriDMSIDParam
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	queryParams, err := FilterQuery(ctx.Request, resources.CMPTransactionFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	out := []resources.CMPTransactionResponse{}
	nextBookmark, err := r.svc.GetCMPTransactionsByDMS(ctx.Request.Context(), services.GetCMPTransactionsByDMSInput{
		DMSID: params.ID,
		ListInput: resources.ListInput[storage.CMPTransaction]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(tx storage.CMPTransaction) {
				out = append(out, cmpTransactionToResponse(tx))
			},
		},
	})
	if err != nil {
		if err == errs.ErrDMSNotFound {
			ctx.JSON(404, gin.H{"err": err.Error()})
			return
		}
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, resources.GetCMPTransactionsResponse{
		IterableList: resources.IterableList[resources.CMPTransactionResponse]{
			NextBookmark: nextBookmark,
			List:         out,
		},
	})
}

// cmpTransactionToResponse adapts the storage row to the wire DTO. It parses
// the cert serial out of CertDER when available so the UI can render a link
// to the cert detail page without having to ship the whole DER blob.
func cmpTransactionToResponse(tx storage.CMPTransaction) resources.CMPTransactionResponse {
	resp := resources.CMPTransactionResponse{
		TransactionID:  tx.TransactionID,
		DMSID:          tx.DMSID,
		State:          string(tx.State),
		IsReenrollment: tx.IsReenrollment,
		CreatedAt:      tx.CreatedAt,
		ExpiresAt:      tx.ExpiresAt,
		ErrorMessage:   tx.ErrorMessage,
		HasCertificate: len(tx.CertDER) > 0,
	}
	if !tx.ConfirmedAt.IsZero() {
		t := tx.ConfirmedAt
		resp.ConfirmedAt = &t
	}
	if tx.CertSerialNumber != "" {
		resp.CertSerialNumber = tx.CertSerialNumber
	} else if len(tx.CertDER) > 0 {
		if cert, perr := x509.ParseCertificate(tx.CertDER); perr == nil {
			resp.CertSerialNumber = serialNumberToHexLower(cert.SerialNumber)
		}
	}
	return resp
}

// serialNumberToHexLower mirrors helpers.SerialNumberToHexString without
// dragging the backend helpers package into this file. The output matches the
// canonical lowercase-hex form Lamassu uses to key its certificate store.
func serialNumberToHexLower(sn *big.Int) string {
	if sn == nil {
		return ""
	}
	return hex.EncodeToString(sn.Bytes())
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

	dms, err := r.svc.CreateDMS(ctx.Request.Context(), input)
	if err != nil {
		ctx.AbortWithStatusJSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(201, dms)
}

func (r *dmsManagerHttpRoutes) UpdateDMS(ctx *gin.Context) {

	var params uriDMSIDParam
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody models.DMS
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.UpdateDMS(ctx.Request.Context(), services.UpdateDMSInput{
		DMS: requestBody,
	})
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, ca)
}

func (r *dmsManagerHttpRoutes) UpdateDMSMetadata(ctx *gin.Context) {
	var params uriDMSIDParam
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateDMSMetadataBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	output, err := r.svc.UpdateDMSMetadata(ctx.Request.Context(), services.UpdateDMSMetadataInput{
		ID:      params.ID,
		Patches: requestBody.Patches,
	})
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, output)
}

func (r *dmsManagerHttpRoutes) DeleteDMS(ctx *gin.Context) {

	var params uriDMSIDParam
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	err := r.svc.DeleteDMS(ctx.Request.Context(), services.DeleteDMSInput{
		ID: params.ID,
	})

	if err != nil {
		switch err {
		case errs.ErrDMSNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.Status(204)
}

func (r *dmsManagerHttpRoutes) BindIdentityToDevice(ctx *gin.Context) {
	var requestBody resources.BindIdentityToDeviceBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	bind, err := r.svc.BindIdentityToDevice(ctx.Request.Context(), services.BindIdentityToDeviceInput{
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
