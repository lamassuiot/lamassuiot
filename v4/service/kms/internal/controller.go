package internal

import (
	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/service/kms"
	"github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/controllers"
)

type kmsHttpRoutes struct {
	svc kms.KMSService
}

func NewKMSHttpRoutes(svc kms.KMSService) *kmsHttpRoutes {
	return &kmsHttpRoutes{
		svc: svc,
	}
}

func (r *kmsHttpRoutes) GetKeys(ctx *gin.Context) {
	queryParams := controllers.FilterQuery(ctx.Request, resources.KMSFilterableFields)

	keys := []kms.Key{}

	nextBookmark, err := r.svc.GetKeys(ctx, kms.GetKeysInput{
		ListInput: resources.ListInput[kms.Key]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(key kms.Key) {
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

	ctx.JSON(200, kms.GetKeysResponse{
		IterableList: resources.IterableList[kms.Key]{
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

	key, err := r.svc.GetKeyByID(ctx, kms.GetKeyByIDInput{
		ID: params.ID,
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
	var requestBody kms.CreateKeyBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := r.svc.CreateKey(ctx, kms.CreateKeyInput{
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

func (r *kmsHttpRoutes) DeleteKeyByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	err := r.svc.DeleteKeyByID(ctx, kms.GetKeyByIDInput{
		ID: params.ID,
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

	var requestBody kms.SignMessageBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	signature, err := r.svc.SignMessage(ctx, kms.SignMessageInput{
		KeyID:       params.ID,
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

	var requestBody kms.VerifySignBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	valid, err := r.svc.VerifySignature(ctx, kms.VerifySignInput{
		KeyID:       params.ID,
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

func (r *kmsHttpRoutes) ImportKey(ctx *gin.Context) {
	var requestBody kms.ImportKeyBody
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

	key, err := r.svc.ImportKey(ctx, kms.ImportKeyInput{
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
