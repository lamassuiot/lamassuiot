package controllers

import (
	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type kmsHttpRoutes struct {
	svc services.KMSService
}

func NewKMSHttpRoutes(svc services.KMSService) *kmsHttpRoutes {
	return &kmsHttpRoutes{
		svc: svc,
	}
}

func (r *kmsHttpRoutes) GetCryptoEngineProvider(ctx *gin.Context) {
	engine, err := r.svc.GetCryptoEngineProvider(ctx.Request.Context())
	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
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
			ctx.JSON(500, gin.H{"err": err.Error()})
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
			ctx.JSON(500, gin.H{"err": err.Error()})
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
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
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
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(201, key)
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
			ctx.JSON(500, gin.H{"err": err.Error()})
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
			ctx.JSON(500, gin.H{"err": err.Error()})
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
			ctx.JSON(500, gin.H{"err": err.Error()})
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
			ctx.JSON(500, gin.H{"err": err.Error()})
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
			ctx.JSON(500, gin.H{"err": err.Error()})
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
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
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
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
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
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(200, stats)
}

func (r *kmsHttpRoutes) RegisterExistingKey(ctx *gin.Context) {
	var requestBody resources.RegisterExistingKeyBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.RegisterExistingKey(ctx.Request.Context(), services.RegisterExistingKeyInput{
		KeyID:    requestBody.KeyID,
		Name:     requestBody.Name,
		Tags:     requestBody.Tags,
		Metadata: requestBody.Metadata,
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

	ctx.JSON(201, key)
}
