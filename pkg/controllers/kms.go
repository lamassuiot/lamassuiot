package controllers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type kmsHttpRoutes struct {
	svc services.KMSService
}

func NewKmsHttpRoutes(svc services.KMSService) *kmsHttpRoutes {
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

func (r *kmsHttpRoutes) CreatePrivateKey(ctx *gin.Context) {
	var requestBody resources.CreatePrivateKeyBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	out, err := r.svc.CreatePrivateKey(ctx, services.CreatePrivateKeyInput{
		EngineID:     requestBody.EngineID,
		KeyAlgorithm: requestBody.KeyAlgorithm,
		KeySize:      requestBody.KeySize,
	})
	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, out)
}

func (r *kmsHttpRoutes) ImportPrivateKey(ctx *gin.Context) {
	var requestBody resources.ImportPrivateKey
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	decodedKey, err := base64.StdEncoding.DecodeString(requestBody.PrivateKey)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var key any
	if len(requestBody.PrivateKey) > 0 {
		key, err = helpers.ParsePrivateKey(decodedKey)
		if err != nil {
			ctx.JSON(400, gin.H{"err": err.Error()})
			return
		}
	}

	var keyType models.KeyType
	var rsaKey *rsa.PrivateKey
	var ecKey *ecdsa.PrivateKey

	switch key.(type) {
	case *rsa.PrivateKey:
		rsaKey = key.(*rsa.PrivateKey)
	case *ecdsa.PrivateKey:
		ecKey = key.(*ecdsa.PrivateKey)
	}

	out, err := r.svc.ImportPrivateKey(ctx, services.ImportPrivateKeyInput{
		EngineID: requestBody.EngineID,
		KeyType:  keyType,
		RSAKey:   rsaKey,
		ECKey:    ecKey,
	})
	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, out)
}

func (r *kmsHttpRoutes) GetKey(ctx *gin.Context) {
	type uriParams struct {
		Kid      string `uri:"kid" binding:"required"`
		EngineID string `uri:"engineId"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	out, err := r.svc.GetKey(ctx, services.GetKeyInput{
		EngineID: params.EngineID,
		KeyID:    params.Kid,
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, out)
}

func (r *kmsHttpRoutes) Sign(ctx *gin.Context) {
	type uriParams struct {
		Kid      string `uri:"kid" binding:"required"`
		EngineID string `uri:"engineId" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.SignatureSignBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	msgDecoded, err := base64.StdEncoding.DecodeString(requestBody.Message)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	out, err := r.svc.Sign(ctx, services.SignInput{
		EngineID:         params.EngineID,
		KeyID:            params.Kid,
		Message:          msgDecoded,
		MessageType:      requestBody.MessageType,
		SigningAlgorithm: requestBody.SigningAlgorithm,
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.SignResponse{
		SignedData: base64.StdEncoding.EncodeToString(out),
	})
}

func (r *kmsHttpRoutes) Verify(ctx *gin.Context) {
	type uriParams struct {
		Kid      string `uri:"kid" binding:"required"`
		EngineID string `uri:"engineId" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.SignatureVerifyBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	msgDecoded, err := base64.StdEncoding.DecodeString(requestBody.Message)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	sigDecoded, err := base64.StdEncoding.DecodeString(requestBody.Signature)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	out, err := r.svc.Verify(ctx, services.VerifyInput{
		EngineID:         params.EngineID,
		KeyID:            params.Kid,
		Signature:        sigDecoded,
		Message:          msgDecoded,
		MessageType:      requestBody.MessageType,
		SigningAlgorithm: requestBody.SigningAlgorithm,
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.VerifyResponse{
		Valid: out,
	})
}
