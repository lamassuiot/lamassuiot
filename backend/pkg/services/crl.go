package services

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/software"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"

	"github.com/lamassuiot/lamassuiot/v4/sdk"
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

func (svc *CRLServiceBackend) SetService(service services.CRLService) {
	svc.service = service
}

func (svc CRLServiceBackend) GetCRL(ctx context.Context, input services.GetCRLInput) (*x509.RevocationList, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

	crlPem, err := svc.bucket.ReadAll(ctx, fmt.Sprintf("pki/va/crl/%s/%s.crl", input.CASubjectKeyID, versionStr))
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

	// CAs sharing a key share the SKI, so the Role: the first of them created it and the others keep it.
	exists, existing, err := svc.vaRepo.Get(ctx, caSki)
	if err != nil {
		return nil, err
	}
	if exists {
		lFunc.Infof("VA role for CA %s already exists, keeping it", caSki)
		return existing, nil
	}

	role, err := svc.vaRepo.Insert(ctx, &models.VARole{
		CASubjectKeyID: caSki,
		CRLOptions: models.VACRLRole{
			Validity:                      models.TimeDuration(24 * time.Hour * 7),            // 1 week
			RefreshInterval:               models.TimeDuration(24*time.Hour*6 + 23*time.Hour), // 6 days, 23 hours
			RegenerateOnRevoke:            true,
			SignerCertificateSerialNumber: ca.Certificate.SerialNumber,
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

	crlCA, signerCert, err := svc.crlIssuer(ctx, input.CASubjectKeyID, vaRole.CRLOptions.SignerCertificateSerialNumber)
	if err != nil {
		return nil, err
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

	crlSigner := NewCertificateSigner(ctx, signerCert, svc.kmsService)
	caCert := (*x509.Certificate)(signerCert.Certificate)

	extensions := []pkix.Extension{}

	idp, err := svc.getDistributionPointExtension(string(crlCA.Certificate.SubjectKeyID))
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
	err = svc.bucket.WriteAll(ctx, fmt.Sprintf("pki/va/crl/%s/%s.crl", input.CASubjectKeyID, crl.Number), crlPem, nil)
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
	return svc.vaRepo.GetAll(ctx, storage.StorageListRequest[models.VARole]{
		ExhaustiveRun: input.ExhaustiveRun,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     map[string]any{},
		ApplyFunc: func(role models.VARole) {
			input.ApplyFunc(role)
		},
	})
}

func (svc CRLServiceBackend) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (*models.VARole, error) {
	exists, role, err := svc.vaRepo.Get(ctx, input.CASubjectKeyID)
	if !exists {
		return nil, errs.ErrVARoleNotFound
	}

	if err != nil {
		return nil, err
	}

	if err := crlValidate.Struct(input); err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	if _, _, err := svc.crlIssuer(ctx, input.CASubjectKeyID, input.CRLRole.SignerCertificateSerialNumber); err != nil {
		return nil, err
	}

	role.CRLOptions = input.CRLRole

	return svc.vaRepo.Update(ctx, role)
}

func (svc CRLServiceBackend) getDistributionPointExtension(aki string) (*pkix.Extension, error) {
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
		idpNames = append(idpNames, asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(fmt.Sprintf("http://%s/crl/%s", name, aki))})
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

// crlIssuer resolves the configured signer certificate and the CA that issues the CRL of the Role of an SKI.
// These are direct CRLs: the signer has the issuer's subject and key, since changing the issuer would require
// indirect-CRL support, not just a different signature. CAs sharing a key share the SKI, so the issuer is the
// CA of the signer, never whichever of them a lookup by SKI finds: the CA whose current certificate the signer
// is or, for a superseded certificate, the oldest CA with its subject and key, as the VA migration chooses.
func (svc CRLServiceBackend) crlIssuer(ctx context.Context, ski, serial string) (*models.CACertificate, *models.Certificate, error) {
	cert, err := svc.caSDK.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: serial})
	if err != nil {
		return nil, nil, err
	}
	signer := (*x509.Certificate)(cert.Certificate)
	signerKey, err := x509.MarshalPKIXPublicKey(signer.PublicKey)
	if err != nil || signer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, nil, errs.ErrValidateBadRequest
	}

	found := false
	var issuer *models.CACertificate
	_, err = svc.caSDK.GetCAs(ctx, services.GetCAsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{{Field: "subject_key_id", Value: ski, FilterOperation: resources.StringEqual}},
		},
		ExhaustiveRun: true,
		ApplyFunc: func(ca models.CACertificate) {
			found = true
			caCert := (*x509.Certificate)(ca.Certificate.Certificate)
			caKey, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
			if err != nil || !bytes.Equal(caCert.RawSubject, signer.RawSubject) || !bytes.Equal(caKey, signerKey) {
				return
			}
			if issuer == nil || crlIssuerPrecedes(ca, *issuer, serial) {
				issuer = &ca
			}
		},
	})
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, errs.ErrCANotFound
	}
	if issuer == nil {
		return nil, nil, errs.ErrValidateBadRequest
	}
	return issuer, cert, nil
}

// crlIssuerPrecedes tells whether a is preferred over b as the issuer of the signer with that serial: the CA
// whose current certificate it is, then the oldest, CAs without creation time last, then the lowest serial.
func crlIssuerPrecedes(a, b models.CACertificate, serial string) bool {
	if aCurrent, bCurrent := a.Certificate.SerialNumber == serial, b.Certificate.SerialNumber == serial; aCurrent != bCurrent {
		return aCurrent
	}
	if a.CreationTS.IsZero() != b.CreationTS.IsZero() {
		return b.CreationTS.IsZero()
	}
	if !a.CreationTS.Equal(b.CreationTS) {
		return a.CreationTS.Before(b.CreationTS)
	}
	return a.Certificate.SerialNumber < b.Certificate.SerialNumber
}
