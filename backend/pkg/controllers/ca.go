package controllers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	cresources "github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
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

// @Summary Create CA
// @Description Create CA
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Param message body resources.CreateCABody true "CA Info"
// @Success 201 {object} models.CACertificate
// @Failure 400 {string} string "Struct Validation error || CA type inconsistent || Issuance expiration greater than CA expiration || Incompatible expiration time ref"
// @Failure 500
// @Router /cas [post]
func (r *caHttpRoutes) CreateCA(ctx *gin.Context) {
	var requestBody resources.CreateCABody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.CreateCA(ctx, services.CreateCAInput{
		ParentID:           requestBody.ParentID,
		ID:                 requestBody.ID,
		KeyMetadata:        requestBody.KeyMetadata,
		Subject:            requestBody.Subject,
		CAExpiration:       requestBody.CAExpiration,
		IssuanceExpiration: requestBody.IssuanceExpiration,
		EngineID:           requestBody.EngineID,
		Metadata:           requestBody.Metadata,
	})
	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAType:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAIssuanceExpiration:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAIncompatibleExpirationTimeRef:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAAlreadyExists:
			ctx.JSON(409, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}
	ctx.JSON(201, ca)
}

func (r *caHttpRoutes) GetStats(ctx *gin.Context) {
	stats, err := r.svc.GetStats(ctx)
	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, stats)
}

func (r *caHttpRoutes) GetStatsByCAID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	stats, err := r.svc.GetStatsByCAID(ctx, services.GetStatsByCAIDInput{
		CAID: params.ID,
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, stats)
}

// @Summary Import CA
// @Description Import CA
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Param message body resources.ImportCABody true "CA Info"
// @Success 201 {object} models.CACertificate
// @Failure 400 {string} string "Struct Validation error || CA type inconsistent || Issuance expiration greater than CA expiration || Incompatible expiration time ref || CA and the provided key dont match"
// @Failure 500
// @Router /cas/import [post]
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

	var key any
	if len(requestBody.CAPrivateKey) > 0 {
		key, err = chelpers.ParsePrivateKey(decodedKey)
		if err != nil {
			ctx.JSON(400, gin.H{"err": err.Error()})
			return
		}
	}

	var keyType cmodels.KeyType
	var rsaKey *rsa.PrivateKey
	var ecKey *ecdsa.PrivateKey

	switch key := key.(type) {
	case *rsa.PrivateKey:
		rsaKey = key
	case *ecdsa.PrivateKey:
		ecKey = key
	}

	ca, err := r.svc.ImportCA(ctx, services.ImportCAInput{
		ID:                 requestBody.ID,
		IssuanceExpiration: requestBody.IssuanceExpiration,
		CAType:             requestBody.CAType,
		CACertificate:      requestBody.CACertificate,
		KeyType:            keyType,
		CARSAKey:           rsaKey,
		CAECKey:            ecKey,
		EngineID:           requestBody.EngineID,
		ParentID:           requestBody.ParentID,
	})
	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAType:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAIssuanceExpiration:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAIncompatibleExpirationTimeRef:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAValidCertAndPrivKey:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}
	ctx.JSON(201, ca)
}

// @Summary Update CA Metadata
// @Description Update CA Metadata
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Param message body resources.UpdateCAMetadataBody true "Update CA Metadata Info"
// @Success 200 {object} models.CACertificate
// @Failure 404 {string} string "CA not found"
// @Failure 400 {string} string "Struct Validation error"
// @Failure 500
// @Router /cas/{id}/metadata [put]
func (r *caHttpRoutes) UpdateCAMetadata(ctx *gin.Context) {
	var requestBody resources.UpdateCAMetadataBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.UpdateCAMetadata(ctx, services.UpdateCAMetadataInput{
		CAID:     params.ID,
		Metadata: requestBody.Metadata,
	})
	if err != nil {
		switch err {
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}
	ctx.JSON(200, ca)
}

func (r *caHttpRoutes) UpdateCAIssuanceExpiration(ctx *gin.Context) {
	var requestBody resources.UpdateCAIssuanceExpirationBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.UpdateCAIssuanceExpiration(ctx, services.UpdateCAIssuanceExpirationInput{
		CAID:               params.ID,
		IssuanceExpiration: requestBody.Expiration,
	})
	if err != nil {
		switch err {
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}
	ctx.JSON(200, ca)
}

func (r *caHttpRoutes) GetCAsByCommonName(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, resources.CAFiltrableFields)

	type uriParams struct {
		CommonName string `uri:"cn" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	cas := []models.CACertificate{}

	nextBookmark, err := r.svc.GetCAsByCommonName(ctx, services.GetCAsByCommonNameInput{
		CommonName:      params.CommonName,
		QueryParameters: queryParams,
		ExhaustiveRun:   false,
		ApplyFunc: func(ca models.CACertificate) {
			cas = append(cas, ca)
		},
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.GetCAsResponse{
		IterableList: resources.IterableList[models.CACertificate]{
			NextBookmark: nextBookmark,
			List:         cas,
		},
	})
}

// @Summary Get All CAs
// @Description Get All CAs
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Success 200 {array} models.CACertificate
// @Failure 500
// @Router /cas [get]
func (r *caHttpRoutes) GetAllCAs(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, resources.CAFiltrableFields)

	cas := []models.CACertificate{}

	nextBookmark, err := r.svc.GetCAs(ctx, services.GetCAsInput{
		QueryParameters: queryParams,
		ExhaustiveRun:   false,
		ApplyFunc: func(ca models.CACertificate) {
			cas = append(cas, ca)
		},
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.GetCAsResponse{
		IterableList: resources.IterableList[models.CACertificate]{
			NextBookmark: nextBookmark,
			List:         cas,
		},
	})
}

// @Summary Get CA By ID
// @Description Get CA By ID
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Success 200 {object} models.CACertificate
// @Failure 404 {string} string "CA not found"
// @Failure 400 {string} string "Struct Validation error"
// @Failure 500
// @Router /cas/{id} [get]
func (r *caHttpRoutes) GetCAByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: params.ID,
	})

	if err != nil {
		switch err {
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, ca)
}

// @Summary Delete CA
// @Description Delete CA
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Success 201
// @Failure 404 {string} string "CA not found"
// @Failure 400 {string} string "Struct Validation error || CA Status inconsistent"
// @Failure 500
// @Router /cas/{id} [delete]
func (r *caHttpRoutes) DeleteCA(ctx *gin.Context) {

	type uriParams struct {
		CAId string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	err := r.svc.DeleteCA(ctx, services.DeleteCAInput{
		CAID: params.CAId,
	})

	if err != nil {
		switch err {
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAStatus:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, gin.H{})
}

func (r *caHttpRoutes) UpdateCAStatus(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateCertificateStatusBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.UpdateCAStatus(ctx, services.UpdateCAStatusInput{
		CAID:             params.ID,
		Status:           requestBody.NewStatus,
		RevocationReason: requestBody.RevocationReason,
	})

	if err != nil {
		switch err {
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrCAAlreadyRevoked:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(201, ca)
}

// @Summary Get Certificate by Serial Number
// @Description Get Certificate by Serial Number
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Success 200 {object} models.Certificate
// @Failure 404 {string} string "Certificate not found"
// @Failure 400 {string} string "Struct Validation error"
// @Failure 500
// @Router /cas/{id}/certificates/{sn} [get]
func (r *caHttpRoutes) GetCertificateBySerialNumber(ctx *gin.Context) {
	type uriParams struct {
		SerialNumber string `uri:"sn" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	cert, err := r.svc.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: params.SerialNumber,
	})

	if err != nil {
		switch err {
		case errs.ErrCertificateNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}
	ctx.JSON(200, cert)
}

// @Summary Get Certificates
// @Description Update CA Metadata
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Param message body resources.UpdateCAMetadataBody true "Update CA Metadata Info"
// @Success 200 {array} models.Certificate
// @Failure 500
// @Router /certificates [get]
func (r *caHttpRoutes) GetCertificates(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, cresources.CertificateFiltrableFields)

	certs := []models.Certificate{}

	nextBookmark, err := r.svc.GetCertificates(ctx, services.GetCertificatesInput{
		ListInput: cresources.ListInput[models.Certificate]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(cert models.Certificate) {
				certs = append(certs, cert)
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

	ctx.JSON(200, resources.GetCertsResponse{
		IterableList: resources.IterableList[models.Certificate]{
			NextBookmark: nextBookmark,
			List:         certs,
		},
	})
}

func (r *caHttpRoutes) GetCertificatesByExpirationDate(ctx *gin.Context) {
	var expirationQueryParams resources.GetCertificatesByExpirationDateQueryParams
	if err := ctx.BindQuery(&expirationQueryParams); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	queryParams := FilterQuery(ctx.Request, cresources.CertificateFiltrableFields)

	certs := []models.Certificate{}

	nextBookmark, err := r.svc.GetCertificatesByExpirationDate(ctx, services.GetCertificatesByExpirationDateInput{
		ExpiresAfter:  expirationQueryParams.ExpiresAfter,
		ExpiresBefore: expirationQueryParams.ExpiresBefore,
		ListInput: cresources.ListInput[models.Certificate]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(cert models.Certificate) {
				certs = append(certs, cert)
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

	ctx.JSON(200, resources.GetCertsResponse{
		IterableList: resources.IterableList[models.Certificate]{
			NextBookmark: nextBookmark,
			List:         certs,
		},
	})
}

// @Summary Get Certificates by CA
// @Description Get Certificates by CA
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Success 200 {array} models.Certificate
// @Failure 404 {string} string "CA not found"
// @Failure 400 {string} string "Struct Validation error"
// @Failure 500
// @Router /cas/{id}/certificates [get]
func (r *caHttpRoutes) GetCertificatesByCA(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, cresources.CertificateFiltrableFields)

	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	certs := []models.Certificate{}

	nextBookmark, err := r.svc.GetCertificatesByCA(ctx, services.GetCertificatesByCAInput{
		CAID: params.ID,
		ListInput: cresources.ListInput[models.Certificate]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(cert models.Certificate) {
				certs = append(certs, cert)
			},
		},
	})
	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.GetCertsResponse{
		IterableList: resources.IterableList[models.Certificate]{
			NextBookmark: nextBookmark,
			List:         certs,
		},
	})
}

// @Summary Sign Certificate
// @Description Sign Certificate
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Param message body resources.SignCertificateBody true "Sign Certificate Info"
// @Success 200 {object} models.Certificate
// @Failure 404 {string} string "CA not found"
// @Failure 400 {string} string "Struct Validation error || CA Status inconsistent"
// @Failure 500
// @Router /cas/{id}/certificates/sign [post]
func (r *caHttpRoutes) SignCertificate(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.SignCertificateBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ca, err := r.svc.SignCertificate(ctx, services.SignCertificateInput{
		CAID:         params.ID,
		Subject:      requestBody.Subject,
		CertRequest:  requestBody.CertRequest,
		SignVerbatim: requestBody.SignVerbatim,
	})
	if err != nil {
		switch err {
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrCAStatus:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(201, ca)
}

func (r *caHttpRoutes) SignatureSign(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
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

	signature, err := r.svc.SignatureSign(ctx, services.SignatureSignInput{
		CAID:             params.ID,
		Message:          msgDecoded,
		MessageType:      requestBody.MessageType,
		SigningAlgorithm: requestBody.SigningAlgorithm,
	})
	if err != nil {
		switch err {
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.SignResponse{
		SignedData: base64.StdEncoding.EncodeToString(signature),
	})
}

func (r *caHttpRoutes) SignatureVerify(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
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

	signDecoded, err := base64.StdEncoding.DecodeString(requestBody.Signature)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	msgDecoded, err := base64.StdEncoding.DecodeString(requestBody.Message)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	valid, err := r.svc.SignatureVerify(ctx, services.SignatureVerifyInput{
		Signature:        signDecoded,
		CAID:             params.ID,
		Message:          msgDecoded,
		MessageType:      requestBody.MessageType,
		SigningAlgorithm: requestBody.SigningAlgorithm,
	})
	if err != nil {
		switch err {
		case errs.ErrCANotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.VerifyResponse{
		Valid: valid,
	})
}

func (r *caHttpRoutes) GetCertificatesByCAAndStatus(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, cresources.CertificateFiltrableFields)

	type uriParams struct {
		CAID   string `uri:"id" binding:"required"`
		Status string `uri:"status" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	certs := []models.Certificate{}

	nextBookmark, err := r.svc.GetCertificatesByCaAndStatus(ctx, services.GetCertificatesByCaAndStatusInput{
		CAID:   params.CAID,
		Status: models.CertificateStatus(params.Status),
		ListInput: cresources.ListInput[models.Certificate]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(cert models.Certificate) {
				certs = append(certs, cert)
			},
		},
	})

	if err != nil {
		switch err {
		case errs.ErrCertificateNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrCertificateStatusTransitionNotAllowed:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.GetCertsResponse{
		IterableList: resources.IterableList[models.Certificate]{
			NextBookmark: nextBookmark,
			List:         certs,
		},
	})
}

func (r *caHttpRoutes) GetCertificatesByStatus(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, cresources.CertificateFiltrableFields)

	type uriParams struct {
		Status string `uri:"status" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	certs := []models.Certificate{}

	nextBookmark, err := r.svc.GetCertificatesByStatus(ctx, services.GetCertificatesByStatusInput{
		Status: models.CertificateStatus(params.Status),
		ListInput: cresources.ListInput[models.Certificate]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(cert models.Certificate) {
				certs = append(certs, cert)
			},
		},
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

	ctx.JSON(200, resources.GetCertsResponse{
		IterableList: resources.IterableList[models.Certificate]{
			NextBookmark: nextBookmark,
			List:         certs,
		},
	})
}

// @Summary Update Certificate Status
// @Description Update Certificate Status
// @Accept json
// @Produce json
// @Security OAuth2Password
// @Param message body resources.UpdateCertificateStatusBody true "Update Certificate status"
// @Success 200 {object} models.Certificate
// @Failure 404 {string} string "Certificate not found"
// @Failure 400 {string} string "Struct Validation error || New status transition not allowed for certificate"
// @Failure 500
// @Router /certificates/{sn}/status [put]
func (r *caHttpRoutes) UpdateCertificateStatus(ctx *gin.Context) {
	type uriParams struct {
		SerialNumber string `uri:"sn" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateCertificateStatusBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	cert, err := r.svc.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
		SerialNumber:     params.SerialNumber,
		NewStatus:        requestBody.NewStatus,
		RevocationReason: requestBody.RevocationReason,
	})

	if err != nil {
		switch err {
		case errs.ErrCertificateNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrCertificateStatusTransitionNotAllowed:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}
	ctx.JSON(200, cert)
}

func (r *caHttpRoutes) UpdateCertificateMetadata(ctx *gin.Context) {
	type uriParams struct {
		SerialNumber string `uri:"sn" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateCertificateMetadataBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	cert, err := r.svc.UpdateCertificateMetadata(ctx, services.UpdateCertificateMetadataInput{
		SerialNumber: params.SerialNumber,
		Metadata:     requestBody.Metadata,
	})

	if err != nil {
		switch err {
		case errs.ErrCertificateNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrCertificateStatusTransitionNotAllowed:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}
	ctx.JSON(200, cert)
}

func (r *caHttpRoutes) ImportCertificate(ctx *gin.Context) {
	var requestBody resources.ImportCertificateBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	cert, err := r.svc.ImportCertificate(ctx, services.ImportCertificateInput{
		Metadata:    requestBody.Metadata,
		Certificate: requestBody.Certificate,
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(201, cert)
}
