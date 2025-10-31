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
	engine, err := r.svc.GetCryptoEngineProvider(ctx)
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
	queryParams := FilterQuery(ctx.Request, resources.KMSFilterableFields)

	keys := []models.Key{}

	nextBookmark, err := r.svc.GetKeys(ctx, services.GetKeysInput{
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

	key, err := r.svc.GetKey(ctx, services.GetKeyInput{
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

	key, err := r.svc.CreateKey(ctx, services.CreateKeyInput{
		Algorithm: requestBody.Algorithm,
		Size:      requestBody.Size,
		EngineID:  requestBody.EngineID,
		Name:      requestBody.Name,
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

	key, err := r.svc.ImportKey(ctx, services.ImportKeyInput{
		PrivateKey: privKey,
		EngineID:   requestBody.EngineID,
		Name:       requestBody.Name,
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

	key, err := r.svc.UpdateKeyAliases(ctx, services.UpdateKeyAliasesInput{
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

	key, err := r.svc.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
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

	key, err := r.svc.UpdateKeyName(ctx, services.UpdateKeyNameInput{
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

func (r *kmsHttpRoutes) DeleteKeyByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	err := r.svc.DeleteKeyByID(ctx, services.GetKeyInput{
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

	signature, err := r.svc.SignMessage(ctx, services.SignMessageInput{
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

	valid, err := r.svc.VerifySignature(ctx, services.VerifySignInput{
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
