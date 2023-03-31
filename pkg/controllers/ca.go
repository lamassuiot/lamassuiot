package controllers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type caHttpRoutes struct {
	svc services.CAService
}

func NewCAHttpRoutes(svc services.CAService) *caHttpRoutes {
	return &caHttpRoutes{
		svc: svc,
	}
}

func (r *caHttpRoutes) GetCryptoEngineProviders(ctx *gin.Context) {
	engines := r.svc.GetCryptoEngineProviders()
	ctx.JSON(200, engines)
}

func (r *caHttpRoutes) CreateCA(ctx *gin.Context) {
	var requestBody resources.CreateCABody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.CreateCA(services.CreateCAInput{
		EngineID:         requestBody.EngineID,
		IssuerCAID:       requestBody.IssuerCAID,
		KeyMetadata:      requestBody.KeyMetadata,
		Subject:          requestBody.Subject,
		IssuanceDuration: requestBody.IssuanceDuration,
		CADuration:       requestBody.CAVailidtyDurarion,
		CAType:           requestBody.CAType,
	})
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
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

	key, err := helppers.ParsePrivateKey(decodedKey)
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
		EngineID:         requestBody.EngineID,
		IssuanceDuration: time.Duration(requestBody.IssuanceDuration),
		CAType:           requestBody.CAType,
		CAChain:          requestBody.CAChain,
		CACertificate:    requestBody.CACertificate,
		KeyType:          keyType,
		CARSAKey:         rsaKey,
		CAECKey:          ecKey,
	})
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
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
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, resources.GetCAsResponse{
		IterbaleList: resources.IterbaleList[models.CACertificate]{
			NextBookmark: nextBookmark,
			List:         cas,
		},
	})
}

func (r *caHttpRoutes) DeleteCA(ctx *gin.Context) {
	err := r.svc.DeleteCA(services.DeleteCAInput{
		ID: "",
	})

	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(201, gin.H{})
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
		ctx.JSON(500, gin.H{"err": err.Error()})
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
		ctx.JSON(500, gin.H{"err": err.Error()})
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
		ctx.JSON(500, gin.H{"err": err.Error()})
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
		Subject:      requestBody.Subject,
		CAID:         params.ID,
		CertRequest:  requestBody.CertRequest,
		SignVerbatim: requestBody.SignVerbatim,
	})
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(201, ca)
}
