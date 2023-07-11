package controllers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

type caHttpRoutes struct {
	svc services.CAService
}

func NewCAHttpRoutes(svc services.CAService) *caHttpRoutes {
	return &caHttpRoutes{
		svc: svc,
	}
}

func (r *caHttpRoutes) GetCryptoEngineProvider(ctx *gin.Context) {
	engine, err := r.svc.GetCryptoEngineProvider()
	if err != nil {
		if err != nil {
			HandleControllerError(ctx, err)
			return
		}
	}
	ctx.JSON(200, engine)
}

func (r *caHttpRoutes) CreateCA(ctx *gin.Context) {
	var requestBody resources.CreateCABody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.CreateCA(services.CreateCAInput{
		KeyMetadata:      requestBody.KeyMetadata,
		Subject:          requestBody.Subject,
		IssuanceDuration: requestBody.IssuanceDuration,
		CADuration:       requestBody.CAVailidtyDurarion,
		CAType:           requestBody.CAType,
	})
	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(201, ca)
}

func (r *caHttpRoutes) ImportCA(ctx *gin.Context) {
	var requestBody resources.ImportCABody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	decodedKey, err := base64.StdEncoding.DecodeString(requestBody.CAPrivateKey)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	key, err := helpers.ParsePrivateKey(decodedKey)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
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

	ca, err := r.svc.ImportCA(services.ImportCAInput{
		IssuanceDuration: time.Duration(requestBody.IssuanceDuration),
		CAType:           requestBody.CAType,
		CAChain:          requestBody.CAChain,
		CACertificate:    requestBody.CACertificate,
		KeyType:          keyType,
		CARSAKey:         rsaKey,
		CAECKey:          ecKey,
	})
	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(201, ca)
}

func (r *caHttpRoutes) GetAllCAs(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request)

	cas := []*models.CACertificate{}
	nextBookmark, err := r.svc.GetCAs(services.GetCAsInput{
		QueryParameters: queryParams,
		ExhaustiveRun:   false,
		ApplyFunc: func(ca *models.CACertificate) {
			cas = append(cas, ca)
		},
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, resources.GetCAsResponse{
		IterbaleList: resources.IterbaleList[models.CACertificate]{
			NextBookmark: nextBookmark,
			List:         cas,
		},
	})
}

func (r *caHttpRoutes) GetCAByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	ca, err := r.svc.GetCAByID(services.GetCAByIDInput{
		CAID: params.ID,
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, ca)
}

func (r *caHttpRoutes) DeleteCA(ctx *gin.Context) {
	err := r.svc.DeleteCA(services.DeleteCAInput{
		CAID: "",
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(201, gin.H{})
}

func (r *caHttpRoutes) RevokeCA(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	var requestBody resources.SignCertificateBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.UpdateCAStatus(services.UpdateCAStatusInput{
		CAID:   params.ID,
		Status: models.StatusRevoked,
	})
	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(201, ca)
}

func (r *caHttpRoutes) GetCertificateBySerialNumber(ctx *gin.Context) {
	type uriParams struct {
		SerialNumber string `uri:"sn" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	cert, err := r.svc.GetCertificateBySerialNumber(services.GetCertificatesBySerialNumberInput{
		SerialNumber: params.SerialNumber,
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, cert)
}

func (r *caHttpRoutes) GetCertificates(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request)

	certs := []*models.Certificate{}
	nextBookmark, err := r.svc.GetCertificates(services.GetCertificatesInput{
		ListInput: services.ListInput[models.Certificate]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(cert *models.Certificate) {
				certs = append(certs, cert)
			},
		},
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, resources.GetCertsResponse{
		IterbaleList: resources.IterbaleList[models.Certificate]{
			NextBookmark: nextBookmark,
			List:         certs,
		},
	})
}

func (r *caHttpRoutes) GetCertificatesByCA(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request)

	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	certs := []*models.Certificate{}
	nextBookmark, err := r.svc.GetCertificatesByCA(services.GetCertificatesByCAInput{
		CAID: params.ID,
		ListInput: services.ListInput[models.Certificate]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(cert *models.Certificate) {
				certs = append(certs, cert)
			},
		},
	})
	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, resources.GetCertsResponse{
		IterbaleList: resources.IterbaleList[models.Certificate]{
			NextBookmark: nextBookmark,
			List:         certs,
		},
	})
}

func (r *caHttpRoutes) SignCertificate(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	var requestBody resources.SignCertificateBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.SignCertificate(services.SignCertificateInput{
		CAID:         params.ID,
		Subject:      requestBody.Subject,
		CertRequest:  requestBody.CertRequest,
		SignVerbatim: requestBody.SignVerbatim,
	})
	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(201, ca)
}

func (r *caHttpRoutes) Sign(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	var requestBody resources.SignBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	decodedDigest, err := base64.StdEncoding.DecodeString(requestBody.Message)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	signedBytes, err := r.svc.Sign(services.SignInput{
		CAID:               params.ID,
		Message:            decodedDigest,
		MessageType:        requestBody.MessageType,
		SignatureAlgorithm: requestBody.SignatureAlgorithm,
	})
	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, resources.SignResponse{
		SignedData: base64.StdEncoding.EncodeToString(signedBytes),
	})
}

func (r *caHttpRoutes) Verify(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	var requestBody resources.VerifyBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	decodedDigest, err := base64.StdEncoding.DecodeString(requestBody.Message)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(requestBody.Signature)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	valid, err := r.svc.VerifySignature(services.VerifySignatureInput{
		CAID:               params.ID,
		Message:            decodedDigest,
		MessageType:        requestBody.MessageType,
		SignatureAlgorithm: requestBody.SignatureAlgorithm,
		Signature:          decodedSignature,
	})
	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, resources.VerifyResponse{
		Valid: valid,
	})
}

func (r *caHttpRoutes) UpdateCertificateStatus(ctx *gin.Context) {
	type uriParams struct {
		SerialNumber string `uri:"sn" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err})
		return
	}

	var requestBody resources.UpdateCertificateStatusBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	cert, err := r.svc.UpdateCertificateStatus(services.UpdateCertificateStatusInput{
		SerialNumber: params.SerialNumber,
		NewStatus:    requestBody.NewStatus,
	})

	if err != nil {
		HandleControllerError(ctx, err)
		return
	}

	ctx.JSON(200, cert)
}
