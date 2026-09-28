package controllers

import (
	"encoding/base64"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type kmsHttpRoutes struct {
	logger *logrus.Entry
	svc    services.KMSService
}

func NewKMSHttpRoutes(logger *logrus.Entry, svc services.KMSService) *kmsHttpRoutes {
	return &kmsHttpRoutes{
		logger: logger,
		svc:    svc,
	}
}

func (r *kmsHttpRoutes) GetCryptoEngineProvider(ctx *gin.Context) {
	engine, err := r.svc.GetCryptoEngineProvider(ctx.Request.Context())
	if err != nil {
		switch err {
		default:
			r.writeInternalError(ctx, err, "could not get crypto engines")
		}

		return
	}

	ctx.JSON(200, engine)
}

func (r *kmsHttpRoutes) GetKeys(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.KMSFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	keys := []models.Key{}

	nextBookmark, err := r.svc.GetKeys(ctx.Request.Context(), services.GetKeysInput{
		ListInput: resources.ListInput[models.Key]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(key models.Key) {
				keys = append(keys, key)
			},
		},
	})
	if err != nil {
		switch err {
		default:
			r.writeInternalError(ctx, err, "could not list keys")
		}

		return
	}

	ctx.JSON(200, resources.GetKeysResponse{
		IterableList: resources.IterableList[models.Key]{
			NextBookmark: nextBookmark,
			List:         keys,
		},
	})

}

func (r *kmsHttpRoutes) GetKeyByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.GetKey(ctx.Request.Context(), services.GetKeyInput{
		Identifier: params.ID,
	})

	if err != nil {
		switch err {
		case errs.ErrKeyNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not get key")
		}

		return
	}

	ctx.JSON(200, key)
}

func (r *kmsHttpRoutes) CreateKey(ctx *gin.Context) {
	var requestBody resources.CreateKeyBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.CreateKey(ctx.Request.Context(), services.CreateKeyInput{
		Algorithm: requestBody.Algorithm,
		Size:      requestBody.Size,
		EngineID:  requestBody.EngineID,
		Name:      requestBody.Name,
		Tags:      requestBody.Tags,
		Metadata:  requestBody.Metadata,
	})

	if err != nil {
		r.writeKeyWriteError(ctx, err, errs.ErrKeyCreationFailed)
		return
	}

	ctx.JSON(201, key)
}

func (r *kmsHttpRoutes) ImportKey(ctx *gin.Context) {
	var requestBody resources.ImportKeyBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	decodedKey, err := base64.StdEncoding.DecodeString(requestBody.PrivateKey)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	if len(decodedKey) == 0 {
		ctx.JSON(400, gin.H{"err": "private key is required"})
		return
	}

	privKey, err := helpers.ParsePrivateKey(decodedKey)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.ImportKey(ctx.Request.Context(), services.ImportKeyInput{
		PrivateKey: privKey,
		EngineID:   requestBody.EngineID,
		Name:       requestBody.Name,
		Tags:       requestBody.Tags,
		Metadata:   requestBody.Metadata,
	})

	if err != nil {
		r.writeKeyWriteError(ctx, err, errs.ErrKeyImportFailed)
		return
	}

	ctx.JSON(201, key)
}

// writeKeyWriteError responde a un fallo al crear o importar una clave: 400 y
// 409 con su error, y para el resto un 500 genérico sin el texto del driver ni
// del engine, que queda en el log del servicio (004 T4.5).
func (r *kmsHttpRoutes) writeKeyWriteError(ctx *gin.Context, err error, generic error) {
	switch {
	case errors.Is(err, errs.ErrValidateBadRequest):
		ctx.JSON(400, gin.H{"err": errs.ErrValidateBadRequest.Error()})
	case errors.Is(err, errs.ErrKeyAlreadyExists):
		ctx.JSON(409, gin.H{"err": errs.ErrKeyAlreadyExists.Error()})
	default:
		r.writeInternalError(ctx, err, generic.Error())
	}
}

// writeInternalError responde con un 500 genérico y uniforme y deja el error
// real (driver, PostgreSQL o engine) solo en el log del servicio, para no
// revelar detalles internos ni de otro tenant (004 T4.9).
func (r *kmsHttpRoutes) writeInternalError(ctx *gin.Context, err error, generic string) {
	helpers.ConfigureLogger(ctx.Request.Context(), r.logger).WithError(err).Errorf("%s %s: %s", ctx.Request.Method, ctx.FullPath(), generic)
	ctx.JSON(500, gin.H{"err": generic})
}

func (r *kmsHttpRoutes) UpdateKeyAliases(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateKeyMetadataBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.UpdateKeyAliases(ctx.Request.Context(), services.UpdateKeyAliasesInput{
		ID:      params.ID,
		Patches: requestBody.Patches,
	})

	if err != nil {
		switch err {
		case errs.ErrKeyNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not update key")
		}
		return
	}

	ctx.JSON(200, key)
}

func (r *kmsHttpRoutes) UpdateKeyMetadata(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateKeyMetadataBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.UpdateKeyMetadata(ctx.Request.Context(), services.UpdateKeyMetadataInput{
		ID:      params.ID,
		Patches: requestBody.Patches,
	})

	if err != nil {
		switch err {
		case errs.ErrKeyNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not update key")
		}
		return
	}

	ctx.JSON(200, key)
}

func (r *kmsHttpRoutes) UpdateKeyName(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateKeyNameBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.UpdateKeyName(ctx.Request.Context(), services.UpdateKeyNameInput{
		ID:   params.ID,
		Name: requestBody.Name,
	})
	if err != nil {
		switch err {
		case errs.ErrKeyNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not update key")
		}
		return
	}

	ctx.JSON(200, key)
}

func (r *kmsHttpRoutes) UpdateKeyTags(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateKeyTagsBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.UpdateKeyTags(ctx.Request.Context(), services.UpdateKeyTagsInput{
		ID:   params.ID,
		Tags: requestBody.Tags,
	})

	if err != nil {
		switch err {
		case errs.ErrKeyNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not update key")
		}
		return
	}

	ctx.JSON(200, key)
}

func (r *kmsHttpRoutes) DeleteKeyByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	err := r.svc.DeleteKeyByID(ctx.Request.Context(), services.GetKeyInput{
		Identifier: params.ID,
	})

	if err != nil {
		switch err {
		case errs.ErrKeyNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not delete key")
		}

		return
	}

	ctx.JSON(200, gin.H{"status": "deleted"})
}

func (r *kmsHttpRoutes) SignMessage(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.SignMessageBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	signature, err := r.svc.SignMessage(ctx.Request.Context(), services.SignMessageInput{
		Identifier:  params.ID,
		Algorithm:   requestBody.Algorithm,
		Message:     requestBody.Message,
		MessageType: requestBody.MessageType,
	})
	if err != nil {
		switch err {
		case errs.ErrKeyNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest, errs.ErrInvalidDigestSize:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not sign message")
		}
		return
	}
	ctx.JSON(200, signature)
}

func (r *kmsHttpRoutes) VerifySignature(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.VerifySignBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	valid, err := r.svc.VerifySignature(ctx.Request.Context(), services.VerifySignInput{
		Identifier:  params.ID,
		Algorithm:   requestBody.Algorithm,
		Signature:   requestBody.Signature,
		Message:     requestBody.Message,
		MessageType: requestBody.MessageType,
	})
	if err != nil {
		switch err {
		case errs.ErrKeyNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest, errs.ErrInvalidDigestSize:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not verify signature")
		}
		return
	}
	ctx.JSON(200, valid)
}

func (r *kmsHttpRoutes) GetStats(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.KMSFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	stats, err := r.svc.GetKeyStats(ctx.Request.Context(), services.GetKeyStatsInput{
		QueryParameters: queryParams,
	})
	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			r.writeInternalError(ctx, err, "could not get key stats")
		}
		return
	}

	ctx.JSON(200, stats)
}
