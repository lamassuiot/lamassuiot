package services

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/x509engines"
	"math/big"
	"time"

	"github.com/go-playground/validator/v10"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"

	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"go.opentelemetry.io/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

var crlValidate *validator.Validate

type CRLServiceBackend struct {
	caSDK      services.CAService
	kmsService services.KMSService
	logger     *logrus.Entry
	vaRepo     storage.VARepo
	service    services.CRLService
	bucket     *blob.Bucket
	vaDomains  []string
}

type CRLServiceBuilder struct {
	VARepo    storage.VARepo
	Logger    *logrus.Entry
	CAClient  services.CAService
	KMSClient services.KMSService
	Bucket    *blob.Bucket
	VADomains []string
}

type CRLMiddleware func(services.CRLService) services.CRLService

func NewCRLService(builder CRLServiceBuilder) (services.CRLService, error) {
	crlValidate = validator.New()

	svc := &CRLServiceBackend{
		caSDK:      builder.CAClient,
		kmsService: builder.KMSClient,
		logger:     builder.Logger,
		vaRepo:     builder.VARepo,
		bucket:     builder.Bucket,
		vaDomains:  builder.VADomains,
	}

	svc.service = svc

	return svc, nil
}

func tenantCRLObjectKey(ctx context.Context, caSKI, version string) (string, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return "", err
	}
	if !validObjectKeyComponent(tenantContext.TenantID) || !validObjectKeyComponent(caSKI) ||
		!validObjectKeyComponent(version) {
		return "", fmt.Errorf("invalid tenant CRL object key components")
	}
	return fmt.Sprintf("pki/va/crl/tenants/%s/%s/%s.crl", tenantContext.TenantID, caSKI, version), nil
}

// readCRLObject reads a CRL from its tenant-scoped key. CRLs written before
// multi-tenancy live under the legacy key pki/va/crl/{ski}/{version}.crl and
// belong to the default tenant: for that tenant a missing object is read from
// the legacy key and copied to the tenant key, so existing CAs keep serving
// their CRL without a separate migration step.
func readCRLObject(ctx context.Context, logger *logrus.Entry, bucket *blob.Bucket, caSKI string, version string) ([]byte, error) {
	objectKey, err := tenantCRLObjectKey(ctx, caSKI, version)
	if err != nil {
		return nil, err
	}
	data, err := bucket.ReadAll(ctx, objectKey)
	if err == nil || gcerrors.Code(err) != gcerrors.NotFound {
		return data, err
	}
	tenantContext, tenantErr := core.RequireTenantContext(ctx)
	if tenantErr != nil || tenantContext.TenantID != models.DefaultTenantID {
		return nil, err
	}
	legacyData, legacyErr := bucket.ReadAll(ctx, fmt.Sprintf("pki/va/crl/%s/%s.crl", caSKI, version))
	if legacyErr != nil {
		return nil, err
	}
	if writeErr := bucket.WriteAll(ctx, objectKey, legacyData, nil); writeErr != nil {
		logger.Warnf("could not copy legacy CRL %s/%s to the tenant key: %s", caSKI, version, writeErr)
	}
	return legacyData, nil
}

func validObjectKeyComponent(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func (svc *CRLServiceBackend) SetService(service services.CRLService) {
	svc.service = service
}

func (svc CRLServiceBackend) GetCRL(ctx context.Context, input services.GetCRLInput) (*x509.RevocationList, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}

	err := crlValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	versionStr := input.CRLVersion.String()
	if input.CRLVersion.Cmp(big.NewInt(0)) == 0 {
		exists, role, err := svc.vaRepo.Get(ctx, input.CASubjectKeyID)
		if err != nil {
			lFunc.Errorf("something went wrong while reading VA role: %s", err)
			return nil, err
		}

		if !exists {
			lFunc.Errorf("VA role for CA %s does not exist", input.CASubjectKeyID)
			return nil, errs.ErrVARoleNotFound
		}

		versionStr = role.LatestCRL.Version.String()
	}

	crlPem, err := readCRLObject(ctx, lFunc, svc.bucket, input.CASubjectKeyID, versionStr)
	if err != nil {
		lFunc.Errorf("something went wrong while reading CRL: %s", err)
		return nil, err
	}

	crlDer, _ := pem.Decode(crlPem)

	crl, err := x509.ParseRevocationList(crlDer.Bytes)
	if err != nil {
		lFunc.Errorf("something went wrong while parsing CRL: %s", err)
		return nil, err
	}

	return crl, nil
}

func (svc CRLServiceBackend) InitCRLRole(ctx context.Context, caSki string) (*models.VARole, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}

	var ca *models.CACertificate
	_, err := svc.caSDK.GetCAs(ctx, services.GetCAsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "subject_key_id",
					FilterOperation: resources.StringEqual,
					Value:           caSki,
				},
			},
		},
		ApplyFunc: func(c models.CACertificate) {
			ca = &c
		},
	})
	if err != nil {
		return nil, err
	}

	if ca == nil {
		lFunc.Errorf("CA %s not found", caSki)
		return nil, errs.ErrCANotFound
	}

	role, err := svc.vaRepo.Insert(ctx, &models.VARole{
		CASubjectKeyID: caSki,
		CRLOptions: models.VACRLRole{
			Validity:           models.TimeDuration(24 * time.Hour * 7),            // 1 week
			RefreshInterval:    models.TimeDuration(24*time.Hour*6 + 23*time.Hour), // 6 days, 23 hours
			RegenerateOnRevoke: true,
			SubjectKeyIDSigner: caSki,
		},
		LatestCRL: models.LatestCRLMeta{
			Version:   models.BigInt{Int: big.NewInt(0)},
			ValidFrom: time.Now(),
		},
	})
	if err != nil {
		return nil, err
	}

	_, err = svc.service.CalculateCRL(ctx, services.CalculateCRLInput{
		CASubjectKeyID: caSki,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while calculating first CRL: %s", err)
		return nil, err
	}

	return role, nil
}

func (svc CRLServiceBackend) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (*x509.RevocationList, error) {
	ctx, span := otel.GetTracerProvider().Tracer("VA Service").Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName("Lamassu-Monolithic")))
	defer span.End()

	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}

	err := crlValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, vaRole, err := svc.vaRepo.Get(ctx, input.CASubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while reading VA role: %s", err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("VA role for CA %s does not exist", input.CASubjectKeyID)
		return nil, errs.ErrVARoleNotFound
	}

	var crlCA *models.CACertificate
	_, err = svc.caSDK.GetCAs(ctx, services.GetCAsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "subject_key_id",
					Value:           input.CASubjectKeyID,
					FilterOperation: resources.StringEqual,
				},
			},
			PageSize: 1,
		},
		ApplyFunc: func(ca models.CACertificate) {
			crlCA = &ca
		},
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading CA %s: %s", input.CASubjectKeyID, err)
		return nil, err
	}

	if crlCA == nil {
		lFunc.Errorf("CA %s not found", input.CASubjectKeyID)
		return nil, errs.ErrCANotFound
	}

	certList := []x509.RevocationListEntry{}
	lFunc.Debugf("reading CA %s certificates", crlCA.ID)
	_, err = svc.caSDK.GetCertificatesByCaAndStatus(ctx, services.GetCertificatesByCaAndStatusInput{
		CAID:   crlCA.ID,
		Status: models.StatusRevoked,
		ListInput: resources.ListInput[models.Certificate]{
			ExhaustiveRun: true,
			QueryParameters: &resources.QueryParameters{
				PageSize: 15,
			},
			ApplyFunc: func(cert models.Certificate) {
				certList = append(certList, x509.RevocationListEntry{
					SerialNumber:   cert.Certificate.SerialNumber,
					RevocationTime: cert.RevocationTimestamp,
					Extensions:     []pkix.Extension{},
					ReasonCode:     int(cert.RevocationReason),
				})
			},
		},
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading CA %s certificates: %s", crlCA.ID, err)
		return nil, err
	}

	crlSigner := NewCertificateSigner(ctx, &crlCA.Certificate, svc.kmsService)
	caCert := (*x509.Certificate)(crlCA.Certificate.Certificate)

	extensions := []pkix.Extension{}

	idp, err := svc.getDistributionPointExtension(ctx, string(crlCA.Certificate.SubjectKeyID))
	if err != nil {
		lFunc.Errorf("something went wrong while creating Issuing Distribution Point extension: %s", err)
		return nil, err
	}

	extensions = append(extensions, *idp)

	lFunc.Debugf("creating revocation list. CA %s", crlCA.ID)
	now := time.Now()

	crlVersion := big.NewInt(0)
	crlVersion.Add(vaRole.LatestCRL.Version.Int, big.NewInt(1))

	entropy := software.NewLamassuEntropy(ctx)

	crlDer, err := x509.CreateRevocationList(entropy, &x509.RevocationList{
		RevokedCertificateEntries: certList,
		Number:                    crlVersion,
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Duration(vaRole.CRLOptions.Validity)),
		ExtraExtensions:           extensions,
	}, caCert, crlSigner)
	if err != nil {
		lFunc.Errorf("something went wrong while creating revocation list: %s", err)
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlDer)
	if err != nil {
		lFunc.Errorf("something went wrong while parsing revocation list: %s", err)
		return nil, err
	}

	crlPem := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDer})
	objectKey, err := tenantCRLObjectKey(ctx, input.CASubjectKeyID, crl.Number.String())
	if err != nil {
		return nil, err
	}
	err = svc.bucket.WriteAll(ctx, objectKey, crlPem, nil)
	if err != nil {
		lFunc.Errorf("something went wrong while saving CRL: %s", err)
		return nil, err
	}

	vaRole.LatestCRL = models.LatestCRLMeta{
		Version:    models.BigInt{Int: crl.Number},
		ValidFrom:  crl.ThisUpdate,
		ValidUntil: crl.NextUpdate,
	}

	_, err = svc.vaRepo.Update(ctx, vaRole)
	if err != nil {
		lFunc.Errorf("something went wrong while updating VA role: %s", err)
		return nil, err
	}

	return crl, nil
}

func (svc CRLServiceBackend) GetVARole(ctx context.Context, input services.GetVARoleInput) (*models.VARole, error) {
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}
	exists, role, err := svc.vaRepo.Get(ctx, input.CASubjectKeyID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errs.ErrVARoleNotFound
	}

	return role, nil
}

func (svc CRLServiceBackend) GetVARoles(ctx context.Context, input services.GetVARolesInput) (string, error) {
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return "", err
	}
	return svc.vaRepo.GetAll(ctx, storage.StorageListRequest[models.VARole]{
		ExhaustiveRun: input.ExhaustiveRun,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     map[string]interface{}{},
		ApplyFunc: func(role models.VARole) {
			input.ApplyFunc(role)
		},
	})
}

func (svc CRLServiceBackend) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (*models.VARole, error) {
	if _, err := core.RequireTenantContext(ctx); err != nil {
		return nil, err
	}
	exists, role, err := svc.vaRepo.Get(ctx, input.CASubjectKeyID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errs.ErrVARoleNotFound
	}

	role.CRLOptions = input.CRLRole

	return svc.vaRepo.Update(ctx, role)
}

func (svc CRLServiceBackend) getDistributionPointExtension(ctx context.Context, aki string) (*pkix.Extension, error) {
	type DistributionPointName struct { // CHOICE
		FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
		RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
	}

	// RFC 5280. Section 5.2.5,
	type IssuingDistributionPoint struct {
		DistributionPoint          DistributionPointName `asn1:"tag:0,optional"`
		OnlyContainsUserCerts      bool                  `asn1:"tag:1"`
		OnlyContainsCACerts        bool                  `asn1:"tag:2"`
		OnlySomeReasons            asn1.BitString        `asn1:"tag:3,optional"`
		IndirectCRL                bool                  `asn1:"tag:4"`
		OnlyContainsAttributeCerts bool                  `asn1:"tag:5"`
	}

	idpNames := []asn1.RawValue{}
	for _, name := range svc.vaDomains {
		idpNames = append(idpNames, asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(x509engines.CRLURL(ctx, name, aki))})
	}

	// Add Issuing Distribution Point
	idp, err := asn1.Marshal(IssuingDistributionPoint{
		DistributionPoint: DistributionPointName{
			FullName: idpNames,
		},
	})
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       []int{2, 5, 29, 28},
		Critical: true,
		Value:    idp,
	}, nil
}
