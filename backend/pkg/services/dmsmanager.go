package services

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	webhookclient "github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers/webhook-client"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/software"
	external_clients "github.com/lamassuiot/lamassuiot/v4/sdk/external"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

var dmsValidate = validator.New()

type DMSManagerMiddleware func(services.DMSManagerService) services.DMSManagerService

type DMSManagerServiceBackend struct {
	service          services.DMSManagerService
	downstreamCert   *x509.Certificate
	dmsStorage       storage.DMSRepo
	deviceManagerCli services.DeviceManagerService
	caClient         services.CAService
	logger           *logrus.Entry
}

type DMSManagerBuilder struct {
	Logger                *logrus.Entry
	DevManagerCli         services.DeviceManagerService
	CAClient              services.CAService
	DMSStorage            storage.DMSRepo
	DownstreamCertificate *x509.Certificate
}

func NewDMSManagerService(builder DMSManagerBuilder) services.DMSManagerService {
	svc := &DMSManagerServiceBackend{
		dmsStorage:       builder.DMSStorage,
		caClient:         builder.CAClient,
		deviceManagerCli: builder.DevManagerCli,
		downstreamCert:   builder.DownstreamCertificate,
		logger:           builder.Logger,
	}

	svc.service = svc

	return svc
}

func (svc *DMSManagerServiceBackend) SetService(service services.DMSManagerService) {
	svc.service = service
}

func (svc DMSManagerServiceBackend) GetDMSStats(ctx context.Context, input services.GetDMSStatsInput) (*models.DMSStats, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	total, err := svc.dmsStorage.CountWithFilters(ctx, input.QueryParameters)
	if err != nil {
		lFunc.Errorf("could not count dmss: %s", err)
		return &models.DMSStats{
			TotalDMSs: -1,
		}, nil
	}

	return &models.DMSStats{
		TotalDMSs: total,
	}, nil
}

func (svc DMSManagerServiceBackend) CreateDMS(ctx context.Context, input services.CreateDMSInput) (*models.DMS, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := dmsValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	if err := validateDMSWebhooks(input.Settings); err != nil {
		lFunc.Errorf("webhook validation error: %s", err)
		return nil, err
	}
	lFunc.Debugf("checking if DMS '%s' exists", input.ID)
	if exists, _, err := svc.dmsStorage.SelectExists(ctx, input.ID); err != nil {
		lFunc.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if exists {
		lFunc.Errorf("DMS '%s' already exist in storage engine", input.ID)
		return nil, errs.ErrDMSAlreadyExists
	}

	dms := &models.DMS{
		ID:           input.ID,
		Name:         input.Name,
		Metadata:     input.Metadata,
		CreationDate: time.Now(),
		Settings:     input.Settings,
	}

	dms, err = svc.dmsStorage.Insert(ctx, dms)
	if err != nil {
		lFunc.Errorf("could not insert DMS '%s': %s", dms.ID, err)
		return nil, err
	}
	lFunc.Debugf("DMS '%s' persisted into storage engine", dms.ID)

	return dms, nil
}

func (svc DMSManagerServiceBackend) UpdateDMS(ctx context.Context, input services.UpdateDMSInput) (*models.DMS, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := dmsValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	if err := validateDMSWebhooks(input.DMS.Settings); err != nil {
		lFunc.Errorf("webhook validation error: %s", err)
		return nil, err
	}
	lFunc.Debugf("checking if DMS '%s' exists", input.DMS.ID)
	exists, dms, err := svc.dmsStorage.SelectExists(ctx, input.DMS.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.DMS.ID, err)
		return nil, err
	} else if !exists {
		lFunc.Errorf("DMS '%s' does not exist in storage engine", input.DMS.ID)
		return nil, errs.ErrDMSNotFound
	}

	dms.Metadata = input.DMS.Metadata
	dms.Name = input.DMS.Name
	dms.Settings = input.DMS.Settings

	lFunc.Debugf("updating DMS %s", input.DMS.ID)
	return svc.dmsStorage.Update(ctx, dms)
}

func (svc DMSManagerServiceBackend) UpdateDMSMetadata(ctx context.Context, input services.UpdateDMSMetadataInput) (*models.DMS, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateDMSMetadata struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if DMS '%s' exists", input.ID)
	exists, dms, err := svc.dmsStorage.SelectExists(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("DMS %s can not be found in storage engine", input.ID)
		return nil, errs.ErrDMSNotFound
	}

	updatedMetadata, err := chelpers.ApplyPatches[map[string]any](dms.Metadata, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to metadata for DMS '%s': %v", input.ID, err)
		return nil, err
	}

	dms.Metadata = *updatedMetadata

	lFunc.Debugf("updating %s DMS metadata", input.ID)
	return svc.dmsStorage.Update(ctx, dms)
}

func (svc DMSManagerServiceBackend) DeleteDMS(ctx context.Context, input services.DeleteDMSInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := dmsValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	id := input.ID
	lFunc.Debugf("checking if DMS '%s' exists", id)
	exists, _, err := svc.dmsStorage.SelectExists(ctx, id)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", id, err)
		return err
	} else if !exists {
		lFunc.Errorf("DMS '%s' does not exist in storage engine", id)
		return errs.ErrDMSNotFound
	}

	err = svc.dmsStorage.Delete(ctx, id)
	if err != nil {
		lFunc.Errorf("something went wrong while deleting the DMS %s %s", id, err)
		return err
	}

	return nil
}

func (svc DMSManagerServiceBackend) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := dmsValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lFunc.Debugf("checking if DMS '%s' exists", input.ID)
	exists, dms, err := svc.dmsStorage.SelectExists(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lFunc.Errorf("DMS '%s' does not exist in storage engine", input.ID)
		return nil, errs.ErrDMSNotFound
	}

	lFunc.Debugf("read DMS %s", dms.ID)

	return dms, nil
}

func (svc DMSManagerServiceBackend) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	bookmark, err := svc.dmsStorage.SelectAll(ctx, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
	if err != nil {
		lFunc.Errorf("something went wrong while reading all DMSs from storage engine: %s", err)
		return "", err
	}

	return bookmark, nil
}

func (svc DMSManagerServiceBackend) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	cas := []*x509.Certificate{}
	lFunc.Debugf("checking if DMS '%s' exists", aps)
	exists, dms, err := svc.dmsStorage.SelectExists(ctx, aps)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", aps, err)
		return nil, err
	} else if !exists {
		lFunc.Errorf("DMS '%s' does not exist in storage engine", aps)
		return nil, errs.ErrDMSNotFound
	}

	caDistribSettings := dms.Settings.CADistributionSettings

	if caDistribSettings.IncludeLamassuSystemCA {
		if svc.downstreamCert == nil {
			lFunc.Warnf("downstream certificate is nil. skipping")
		} else {
			cas = append(cas, svc.downstreamCert)
		}
	}

	reqCAs := []string{}
	reqCAs = append(reqCAs, dms.Settings.CADistributionSettings.ManagedCAs...)

	if caDistribSettings.IncludeEnrollmentCA {
		reqCAs = append(reqCAs, dms.Settings.EnrollmentSettings.EnrollmentCA)
	}

	for _, ca := range reqCAs {
		lFunc.Debugf("Reading CA %s Certificate", ca)
		caResponse, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{
			CAID: ca,
		})
		if err != nil {
			lFunc.Errorf("something went wrong while reading CA '%s' by ID: %s", ca, err)
			return nil, err
		}

		lFunc.Debugf("got CA %s\n%s", caResponse.ID, chelpers.CertificateToPEM((*x509.Certificate)(caResponse.Certificate.Certificate)))

		cas = append(cas, (*x509.Certificate)(caResponse.Certificate.Certificate))
	}

	return cas, nil
}

func getESTLogFormatter() logrus.Formatter {
	formatter := *chelpers.LogFormatter
	formatter.FieldsOrder = append(formatter.FieldsOrder, "func")
	formatter.FieldsOrder = append(formatter.FieldsOrder, "dms")
	formatter.FieldsOrder = append(formatter.FieldsOrder, "device-cn")
	formatter.FieldsOrder = append(formatter.FieldsOrder, "step")
	formatter.FieldsOrder = append(formatter.FieldsOrder, "auth-method")
	formatter.FieldsOrder = append(formatter.FieldsOrder, "auth-status")
	formatter.FieldsOrder = append(formatter.FieldsOrder, "auth-uri")

	return &formatter
}

// validateClientCertificateEnrollment validates the client certificate chain against the DMS's configured
// client certificate validation CAs and performs a revocation check. clientCerts must be non-empty.
func (svc DMSManagerServiceBackend) validateClientCertificateEnrollment(ctx context.Context, lFunc *logrus.Entry, estAuthOptions models.EnrollmentOptionsESTRFC7030, clientCerts []*x509.Certificate) (*logrus.Entry, error) {
	leafClientCert := clientCerts[0]
	mtlsOpts := estAuthOptions.AuthOptionsMTLS

	lFunc = lFunc.WithField("auth-status", "verifying")
	lFunc = lFunc.WithField("auth-uri", fmt.Sprintf("CN=%s, SN=%s, Issuer=%s", leafClientCert.Subject.CommonName, helpers.SerialNumberToHexString(leafClientCert.SerialNumber), leafClientCert.Issuer.CommonName))
	lFunc.Debugf("presented client certificate")

	if mtlsOpts.AllowExpired {
		lFunc.Warnf("enrollment with expired certificates is allowed by DMS")
	} else {
		lFunc.Debugf("enrollment with expired certificates is NOT allowed by DMS")
	}

	if mtlsOpts.ChainLevelValidation > 0 && len(clientCerts) > mtlsOpts.ChainLevelValidation {
		lFunc.Warnf("presented client certificate chain has more levels than allowed by DMS configuration. Chain levels: %d, Allowed levels: %d. Trimming certificate chain validation to %d levels", len(clientCerts), mtlsOpts.ChainLevelValidation, mtlsOpts.ChainLevelValidation)
		clientCerts = clientCerts[:mtlsOpts.ChainLevelValidation]
	}

	var validationCA *models.CACertificate
	for _, caID := range mtlsOpts.ValidationCAs {
		ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
		if err != nil {
			lFunc.Warnf("could not obtain lamassu CA '%s'. Skipping to next validation CA: %s", caID, err)
			continue
		}
		err = helpers.ValidateCertificates((*x509.Certificate)(ca.Certificate.Certificate), clientCerts, !mtlsOpts.AllowExpired)
		if err != nil {
			lFunc.Debugf("invalid validation using CA [%s] with CommonName '%s', SerialNumber '%s'", ca.ID, ca.Certificate.Subject.CommonName, ca.Certificate.SerialNumber)
			continue
		}
		lFunc.Infof("certificate validated. Revocation check will be performed next")
		validationCA = ca
		break
	}

	if validationCA == nil {
		lFunc.WithField("auth-status", "failed").Errorf("aborting enrollment. used certificate not authorized for this DMS")
		return lFunc, errs.ErrDMSEnrollInvalidCert
	}

	issuer := leafIssuer(leafClientCert, (*x509.Certificate)(validationCA.Certificate.Certificate), clientCerts[1:])
	if err := svc.verifyCertificateNotRevoked(ctx, lFunc, leafClientCert, issuer, mtlsOpts.AllowUnverifiableRevocation, "enrollment"); err != nil {
		return lFunc, err
	}

	return lFunc, nil
}

// validateClientCertificateReenrollment validates the presented client certificate for re-enrollment.
// It checks that the certificate's CommonName matches the CSR subject, then checks against the
// enrollment CA first, then falls back to the re-enrollment validation CAs,
// and finally verifies expiry and revocation status.
func (svc DMSManagerServiceBackend) validateClientCertificateReenrollment(ctx context.Context, lFunc *logrus.Entry, enrollCAID string, enrollCA *models.CACertificate, reEnrollSettings models.ReEnrollmentSettings, clientCerts []*x509.Certificate, csrSubjectCN string) (*logrus.Entry, error) {
	leafCert := clientCerts[0]

	lFunc = lFunc.WithField("auth-status", "verifying")
	lFunc = lFunc.WithField("auth-uri", fmt.Sprintf("CN=%s, SN=%s, Issuer=%s", leafCert.Subject.CommonName, helpers.SerialNumberToHexString(leafCert.SerialNumber), leafCert.Issuer.CommonName))
	lFunc.Debugf("presented client certificate")

	if leafCert.Subject.CommonName != csrSubjectCN {
		lFunc.WithField("auth-status", "failed").Errorf("aborting reenrollment. certificate CommonName '%s' does not match CSR subject CommonName '%s'", leafCert.Subject.CommonName, csrSubjectCN)
		return lFunc, errs.ErrDMSEnrollInvalidCert
	}

	validationCA := svc.findReenrollmentValidationCA(ctx, lFunc, enrollCAID, enrollCA, reEnrollSettings, leafCert)
	if validationCA == nil {
		caAki := string(leafCert.AuthorityKeyId)
		lFunc.WithField("auth-status", "failed").Errorf("aborting reenrollment process. Unknown CA:\nCN: %s\nAKI:%s", leafCert.Issuer.CommonName, caAki)
		return lFunc, errs.ErrDMSEnrollInvalidCert
	}

	if err := checkReenrollmentExpiry(lFunc, leafCert, reEnrollSettings); err != nil {
		return lFunc, err
	}

	lFunc.Infof("checking certificate revocation status")
	allowUnverifiable := reEnrollSettings.ReEnrollmentOptionsESTRFC7030.AuthOptionsMTLS.AllowUnverifiableRevocation
	if err := svc.verifyCertificateNotRevoked(ctx, lFunc, leafCert, validationCA, allowUnverifiable, "reenrollment"); err != nil {
		return lFunc, err
	}

	return lFunc, nil
}

// leafIssuer returns the certificate that directly signed leaf: one of the presented intermediates or, if none
// did, the validation CA. OCSP requests and CRL/OCSP signature checks for leaf must use this issuer.
func leafIssuer(leaf, validationCA *x509.Certificate, intermediates []*x509.Certificate) *x509.Certificate {
	for _, candidate := range intermediates {
		if bytes.Equal(leaf.RawIssuer, candidate.RawSubject) && leaf.CheckSignatureFrom(candidate) == nil {
			return candidate
		}
	}
	return validationCA
}

// verifyCertificateNotRevoked fails closed: it returns nil only when cert is known not to be revoked, or when
// there is no revocation source to consult at all and allowUnverifiable is set.
func (svc DMSManagerServiceBackend) verifyCertificateNotRevoked(ctx context.Context, lFunc *logrus.Entry, cert, issuer *x509.Certificate, allowUnverifiable bool, operation string) error {
	status, err := svc.checkCertificateRevocation(ctx, cert, issuer)
	if err != nil {
		lFunc.WithField("auth-status", "failed").Errorf("aborting %s. could not verify certificate revocation status: %s", operation, err)
		return fmt.Errorf("could not verify certificate revocation status: %w", err)
	}

	switch status {
	case revocationStatusGood:
		lFunc.Infof("certificate is not revoked")
		return nil
	case revocationStatusRevoked:
		lFunc.WithField("auth-status", "failed").Errorf("aborting %s. certificate is revoked", operation)
		return fmt.Errorf("certificate is revoked")
	default:
		if allowUnverifiable {
			lFunc.Warnf("certificate is not managed by Lamassu and has no OCSP/CRL endpoints. Accepting it because DMS allows unverifiable revocation status")
			return nil
		}
		lFunc.WithField("auth-status", "failed").Errorf("aborting %s. certificate is not managed by Lamassu and has no OCSP/CRL endpoints to check its revocation status", operation)
		return fmt.Errorf("certificate revocation status cannot be verified: certificate is not managed by Lamassu and has no OCSP/CRL endpoints")
	}
}

// findReenrollmentValidationCA tries the enrollment CA first, then each of the re-enrollment validation CAs.
// Returns the matching CA's certificate, or nil if none validated the leaf.
func (svc DMSManagerServiceBackend) findReenrollmentValidationCA(ctx context.Context, lFunc *logrus.Entry, enrollCAID string, enrollCA *models.CACertificate, reEnrollSettings models.ReEnrollmentSettings, leafCert *x509.Certificate) *x509.Certificate {
	enrollCACert := (*x509.Certificate)(enrollCA.Certificate.Certificate)

	lFunc.Debugf("validating client certificate using EST Enrollment CA which has ID=%s CN=%s SN=%s", enrollCAID, enrollCA.Certificate.Subject.CommonName, enrollCA.Certificate.SerialNumber)
	if err := helpers.ValidateCertificate(enrollCACert, leafCert, false); err == nil {
		lFunc.Infof("certificate validated. Revocation and Expiration (if needed) check will be performed next")
		return enrollCACert
	}
	lFunc.Warnf("invalid validation using enroll CA. Will try validating using re-enrollment validation CAs")

	validationCAs := reEnrollSettings.ReEnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs
	aValCAsCtr := len(validationCAs)
	lFunc.Debugf("DMS has %d re-enrollment validation CAs", aValCAsCtr)

	for idx, caID := range validationCAs {
		lFunc.Debugf("[%d/%d] obtaining validation with ID %s", idx, aValCAsCtr, caID)
		ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
		if err != nil {
			lFunc.Warnf("[%d/%d] could not obtain lamassu CA with ID %s. Skipping to next validation CA: %s", idx, aValCAsCtr, caID, err)
			continue
		}
		caCert := (*x509.Certificate)(ca.Certificate.Certificate)
		if err = helpers.ValidateCertificate(caCert, leafCert, false); err != nil {
			lFunc.Debugf("[%d/%d] invalid validation using CA [%s] with CommonName '%s', SerialNumber '%s'", idx, aValCAsCtr, ca.ID, ca.Certificate.Subject.CommonName, ca.Certificate.SerialNumber)
			continue
		}
		lFunc.Debugf("[%d/%d] OK validation using CA [%s] with CommonName '%s', SerialNumber '%s'", idx, aValCAsCtr, ca.ID, ca.Certificate.Subject.CommonName, ca.Certificate.SerialNumber)
		return caCert
	}

	return nil
}

// checkReenrollmentExpiry logs the expiry policy and returns an error if the certificate is
// expired and the DMS does not allow expired renewals.
func checkReenrollmentExpiry(lFunc *logrus.Entry, leafCert *x509.Certificate, reEnrollSettings models.ReEnrollmentSettings) error {
	if reEnrollSettings.EnableExpiredRenewal {
		lFunc.Warnf("DMS configured to allow reenrollment with expired certificates")
	} else {
		lFunc.Info("DMS configured to NOT allow reenrollment with expired certificates")
	}

	if time.Now().After(leafCert.NotAfter) {
		if reEnrollSettings.EnableExpiredRenewal {
			lFunc.Warnf("presented an expired certificate: %s", time.Since(leafCert.NotBefore))
			return nil
		}
		lFunc.WithField("auth-status", "failed").Errorf("aborting reenrollment. device has a valid but expired certificate")
		return fmt.Errorf("expired certificate")
	}

	return nil
}

// validateDMSWebhooks rejects external webhook configs that would fail on
// every enroll or reenroll, so the error surfaces when the DMS is configured.
func validateDMSWebhooks(settings models.DMSSettings) error {
	webhooks := []struct {
		operation string
		opts      models.EnrollmentOptionsESTRFC7030
	}{
		{"enrollment", settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030},
		{"reenrollment", settings.ReEnrollmentSettings.ReEnrollmentOptionsESTRFC7030},
	}
	for _, w := range webhooks {
		switch w.opts.AuthMode {
		case models.ESTAuthModeExternalWebhook, models.ESTAuthModeClientCertificateAndWebhook:
		default:
			continue
		}
		if err := webhookclient.ValidateWebhook(w.opts.AuthOptionsExternalWebhook); err != nil {
			return fmt.Errorf("%w: invalid %s external webhook config: %s", errs.ErrValidateBadRequest, w.operation, err)
		}
	}
	return nil
}

// invokeWebhook calls the configured external webhook and returns an error if the
// webhook denies the operation or cannot be reached (fail-closed).
// operation should be "enrollment" or "reenrollment" and is used in log messages and errors.
func invokeWebhook(ctx context.Context, lFunc *logrus.Entry, webhookConf models.WebhookCall, csr *x509.CertificateRequest, aps string, operation string) (*logrus.Entry, error) {
	lFunc = lFunc.WithField("auth-status", "verifying")
	lFunc = lFunc.WithField("auth-uri", webhookConf.Url)
	lFunc.Infof("verifying %s using external webhook: %s. Calling webhook %s", operation, webhookConf.Name, webhookConf.Url)

	webhookRequestBodyHeaders := make(map[string]string)
	requestURL := ""
	httpReq, ok := ctx.Value(core.LamassuContextKeyHTTPRequest).(*http.Request)
	if ok && httpReq != nil {
		for key, values := range httpReq.Header {
			if len(values) > 0 {
				webhookRequestBodyHeaders[key] = values[0]
			}
		}
		requestURL = httpReq.URL.String()
	}

	pemCsr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	b64EncodedCsr := base64.StdEncoding.EncodeToString(pemCsr)

	webhookRequestBody := map[string]any{
		"csr":       b64EncodedCsr,
		"aps":       aps,
		"device_cn": csr.Subject.CommonName,
		"http_request": map[string]any{
			"headers": webhookRequestBodyHeaders,
			"url":     requestURL,
		},
	}

	type webhookResponse struct {
		Authorized bool `json:"authorized"`
	}

	webhookTimeout := webhookclient.DefaultCallTimeout
	if webhookConf.Config.CallTimeout > 0 {
		webhookTimeout = time.Duration(webhookConf.Config.CallTimeout)
	}
	webhookCtx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()

	resp, err := webhookclient.InvokeJSONWebhook[webhookResponse](webhookCtx, lFunc, webhookConf, webhookRequestBody)
	if err != nil {
		if ctxErr := webhookCtx.Err(); ctxErr != nil {
			lFunc.WithField("auth-status", "failed").Errorf("aborting %s. external webhook authorization did not complete before deadline: %s", operation, ctxErr)
			return lFunc, fmt.Errorf("external webhook authorization timed out or was canceled: %w", ctxErr)
		}
		lFunc.WithField("auth-status", "failed").Errorf("aborting %s. got error while calling external webhook: %s", operation, err)
		return lFunc, fmt.Errorf("error while calling external webhook: %s", err)
	}
	lFunc.Debugf("webhook response: %v", resp)
	if resp == nil {
		lFunc.WithField("auth-status", "failed").Errorf("aborting %s. external webhook didn't return a response", operation)
		return lFunc, fmt.Errorf("external webhook didn't return a response")
	}
	if !resp.Authorized {
		lFunc.WithField("auth-status", "failed").Errorf("aborting %s. external webhook denied %s", operation, operation)
		return lFunc, fmt.Errorf("external webhook denied %s", operation)
	}

	lFunc.Infof("webhook authorized %s", operation)
	return lFunc, nil
}

// clientCertValidator is a function type used by authenticateEST to delegate
// the per-operation (enroll / reenroll) certificate-chain validation logic.
type clientCertValidator func(ctx context.Context, lFunc *logrus.Entry, clientCerts []*x509.Certificate) (*logrus.Entry, error)

// authenticateEST runs the authentication step shared by Enroll and Reenroll,
// dispatching to the appropriate handler based on estAuthOptions.AuthMode.
// validateCert is called whenever the auth mode requires a client certificate;
// its implementation differs between enrollment and reenrollment.
func (svc DMSManagerServiceBackend) authenticateEST(
	ctx context.Context,
	lFunc *logrus.Entry,
	estAuthOptions models.EnrollmentOptionsESTRFC7030,
	csr *x509.CertificateRequest,
	aps string,
	operation string,
	validateCert clientCertValidator,
) (*logrus.Entry, error) {
	var err error
	switch estAuthOptions.AuthMode {
	case models.ESTAuthModeClientCertificate:
		lFunc = lFunc.WithField("auth-method", models.ESTAuthModeClientCertificate)
		var clientCerts []*x509.Certificate
		if singleCert, ok := ctx.Value(core.LamassuContextKeyAuthCredentialStruct).(*x509.Certificate); ok && singleCert != nil {
			clientCerts = []*x509.Certificate{singleCert}
		}
		if len(clientCerts) == 0 {
			lFunc.Errorf("aborting %s. No client certificate was presented", operation)
			return lFunc, errs.ErrDMSAuthModeNotSupported
		}
		lFunc, err = validateCert(ctx, lFunc, clientCerts)
		if err != nil {
			return lFunc, err
		}
		lFunc = lFunc.WithField("auth-status", "verified")
		lFunc.Infof("certificate verified")

	case models.ESTAuthModeNoAuth:
		lFunc = lFunc.WithField("auth-method", models.ESTAuthModeNoAuth)
		lFunc = lFunc.WithField("auth-status", "verified")
		lFunc = lFunc.WithField("auth-uri", "NoAuth")
		lFunc.Warnf("DMS is configured with NoAuth, allowing %s", operation)

	case models.ESTAuthModeExternalWebhook:
		lFunc = lFunc.WithField("auth-method", models.ESTAuthModeExternalWebhook)
		lFunc, err = invokeWebhook(ctx, lFunc, estAuthOptions.AuthOptionsExternalWebhook, csr, aps, operation)
		if err != nil {
			return lFunc, err
		}
		lFunc = lFunc.WithField("auth-status", "verified")
		lFunc.Infof("external webhook authorized %s", operation)

	case models.ESTAuthModeClientCertificateAndWebhook:
		lFunc = lFunc.WithField("auth-method", models.ESTAuthModeClientCertificateAndWebhook)
		lFunc.Infof("combined auth: starting client certificate validation (step 1/2)")
		var clientCerts []*x509.Certificate
		if singleCert, ok := ctx.Value(core.LamassuContextKeyAuthCredentialStruct).(*x509.Certificate); ok && singleCert != nil {
			clientCerts = []*x509.Certificate{singleCert}
		}
		if len(clientCerts) == 0 {
			lFunc = lFunc.WithField("auth-status", "failed")
			lFunc.Errorf("aborting %s. No client certificate was presented", operation)
			return lFunc, errs.ErrDMSAuthModeNotSupported
		}
		lFunc, err = validateCert(ctx, lFunc, clientCerts)
		if err != nil {
			return lFunc, err
		}
		lFunc.Infof("combined auth: client certificate validation passed. Starting webhook validation (step 2/2)")
		lFunc, err = invokeWebhook(ctx, lFunc, estAuthOptions.AuthOptionsExternalWebhook, csr, aps, operation)
		if err != nil {
			return lFunc, err
		}
		lFunc = lFunc.WithField("auth-status", "verified")
		lFunc.Infof("combined auth: both client certificate and webhook validations passed")

	default:
		lFunc.Errorf("aborting %s. DMS is not correctly configured. No auth method configured. Specify an authentication method", operation)
		return lFunc, errs.ErrDMSAuthModeNotSupported
	}

	return lFunc, nil
}

// Validation:
//   - Cert:
//     Only Bootstrap cert (CA issued By Lamassu)
func (svc DMSManagerServiceBackend) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Logger.SetFormatter(getESTLogFormatter())

	lFunc = lFunc.WithField("func", "Enroll")
	lFunc = lFunc.WithField("dms", aps)
	lFunc = lFunc.WithField("device-cn", csr.Subject.CommonName)
	lFunc = lFunc.WithField("step", "PreEnroll")

	lFunc.Infof("starting enrollment process for device")

	lFunc.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lFunc.Errorf("aborting enrollment. Could not get DMS '%s': %s", aps, err)
		return nil, errs.ErrDMSNotFound
	}

	lFunc = lFunc.WithField("dms", dms.ID)
	enrollSettings := dms.Settings.EnrollmentSettings

	if enrollSettings.EnrollmentProtocol != models.EST {
		lFunc.Errorf("aborting enrollment. DMS doesn't support EST Protocol")
		return nil, errs.ErrDMSOnlyEST
	}

	estAuthOptions := enrollSettings.EnrollmentOptionsESTRFC7030

	lFunc = lFunc.WithField("step", "Authenticating")
	lFunc.Infof("starting authentication process")

	validateCert := func(ctx context.Context, lFunc *logrus.Entry, clientCerts []*x509.Certificate) (*logrus.Entry, error) {
		return svc.validateClientCertificateEnrollment(ctx, lFunc, estAuthOptions, clientCerts)
	}
	lFunc, err = svc.authenticateEST(ctx, lFunc, estAuthOptions, csr, aps, "enrollment", validateCert)
	if err != nil {
		return nil, err
	}

	lFunc.Infof("authentication process completed successfully")

	lFunc = lFunc.WithField("step", "CSRCheck")
	if enrollSettings.VerifyCSRSignature {
		err = checkCSRSignature(lFunc, csr, "enrollment")
		if err != nil {
			return nil, fmt.Errorf("invalid CSR signature")
		}
	} else {
		lFunc.Warn("DMS is configured with no CSR signature verification, allowing enrollment")
	}

	lFunc = lFunc.WithField("step", "DeviceReg")

	var device *models.Device
	device, err = svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: csr.Subject.CommonName,
	})
	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			lFunc.Debugf("device '%s' doesn't exist", csr.Subject.CommonName)
		default:
			lFunc.Errorf("could not get device '%s': %s", csr.Subject.CommonName, err)
			return nil, err
		}
	} else {
		lFunc.Debugf("device '%s' does exist", csr.Subject.CommonName)
		if device.DMSOwner != dms.ID {
			lFunc.Errorf("aborting enrollment. device '%s' is registered with DMS '%s'", csr.Subject.CommonName, device.DMSOwner)
			return nil, fmt.Errorf("device already registered to another DMS")
		}

		if enrollSettings.EnableReplaceableEnrollment {
			lFunc.Debugf("DMS allows new enrollments. Continuing enrollment for device '%s'", csr.Subject.CommonName)
			//revoke active certificate
			defer func() {
				lFunc = lFunc.WithField("step", "PostEnroll")
				lFunc.Infof("starting PostEnroll process")
				if device.IdentitySlot == nil {
					device.IdentitySlot = &models.Slot[string]{}
				}
				_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
					SerialNumber:     device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion],
					NewStatus:        models.StatusRevoked,
					RevocationReason: ocsp.Superseded,
				})
				if err != nil {
					lFunc.Warnf("could not revoke certificate %s: %s", device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion], err)
				} else {
					lFunc.Infof("revoked certificate %s successfully", device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion])
				}

				lFunc.Infof("PostEnroll process completed successfully")
			}()
		} else {
			lFunc.Debugf("aborting enrollment. DMS forbids new enrollments. consider switching NewEnrollment option ON in the DMS")
			return nil, fmt.Errorf("forbiddenNewEnrollment")
		}
	}

	if enrollSettings.RegistrationMode == models.JITP {
		if device == nil {
			lFunc.Debugf("DMS is configured with JustInTime registration. will create device with ID %s", csr.Subject.CommonName)
			//contact device manager and register device first
			device, err = svc.deviceManagerCli.CreateDevice(ctx, services.CreateDeviceInput{
				ID:        csr.Subject.CommonName,
				Alias:     csr.Subject.CommonName,
				Tags:      enrollSettings.DeviceProvisionProfile.Tags,
				Metadata:  enrollSettings.DeviceProvisionProfile.Metadata,
				Icon:      enrollSettings.DeviceProvisionProfile.Icon,
				IconColor: enrollSettings.DeviceProvisionProfile.IconColor,
				DMSID:     dms.ID,
			})
			if err != nil {
				lFunc.Errorf("could not register device: %s", err)
				return nil, err
			}
		} else {
			lFunc.Debugf("skipping device registration since already exists")
		}
	} else if device == nil {
		lFunc.Errorf("aborting enrollment. DMS doesn't allow JustInTime registration. register the device manually or switch DMS JIT option ON")
		return nil, fmt.Errorf("device not preregistered")
	} else {
		lFunc.Infof("device %s already preregistered. continuing enrollment process", device.ID)
	}

	lFunc.Infof("device registration process completed successfully")

	lFunc = lFunc.WithField("step", "Signature")
	lFunc.Infof("starting signature process")

	issuanceProfile, err := svc.resolveIssuanceProfile(ctx, lFunc, dms, enrollSettings.EnrollmentCA)
	if err != nil {
		return nil, err
	}

	lFunc.Infof("requesting certificate signature")
	crt, err := svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
		CAID:            enrollSettings.EnrollmentCA,
		CertRequest:     (*models.X509CertificateRequest)(csr),
		IssuanceProfile: issuanceProfile,
	})
	if err != nil {
		lFunc.Errorf("could not issue certificate for device: %s", err)
		return nil, err
	}

	bindMode := models.DeviceEventTypeProvisioned
	if device.IdentitySlot == nil {
		bindMode = models.DeviceEventTypeProvisioned
	} else {
		bindMode = models.DeviceEventTypeReProvisioned
	}

	lFunc.Infof("assigning certificate to device")
	_, err = svc.service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                bindMode,
	})
	if err != nil {
		lFunc.Errorf("could not assign certificate to device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	lFunc.Infof("certificate signing process completed successfully")

	lFunc = lFunc.WithField("step", "Done")
	lFunc.Infof("enrollment process completed successfully")

	return (*x509.Certificate)(crt.Certificate), nil
}

func (svc DMSManagerServiceBackend) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Logger.SetFormatter(getESTLogFormatter())

	lFunc = lFunc.WithField("func", "ReEnroll")
	lFunc = lFunc.WithField("dms", aps)
	lFunc = lFunc.WithField("device-cn", csr.Subject.CommonName)
	lFunc = lFunc.WithField("step", "PreReEnroll")

	lFunc.Infof("starting reenrollment process for device")

	if csr.Subject.CommonName == "" {
		lFunc.Errorf("aborting reenrollment. No CommonName in CSR")
		return nil, fmt.Errorf("no CommonName in CSR")
	}

	lFunc.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lFunc.Errorf("aborting reenrollment. Could not get DMS: %s", err)
		return nil, errs.ErrDMSNotFound
	}

	lFunc = lFunc.WithField("dms", dms.ID)
	enrollSettings := dms.Settings.EnrollmentSettings
	if enrollSettings.EnrollmentProtocol != models.EST {
		lFunc.Errorf("aborting reenrollment. DMS doesn't support EST Protocol")
		return nil, errs.ErrDMSOnlyEST
	}

	enrollCAID := enrollSettings.EnrollmentCA
	enrollCA, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: enrollCAID,
	})
	if err != nil {
		lFunc.Errorf("could not get enroll CA with ID=%s: %s", enrollCAID, err)
		return nil, err
	}

	reEnrollSettings := dms.Settings.ReEnrollmentSettings
	reEnrollAuthSettings := reEnrollSettings.ReEnrollmentOptionsESTRFC7030

	lFunc = lFunc.WithField("step", "Authenticating")
	lFunc.Infof("starting authentication process")

	validateCert := func(ctx context.Context, lFunc *logrus.Entry, clientCerts []*x509.Certificate) (*logrus.Entry, error) {
		return svc.validateClientCertificateReenrollment(ctx, lFunc, enrollCAID, enrollCA, reEnrollSettings, clientCerts, csr.Subject.CommonName)
	}
	lFunc, err = svc.authenticateEST(ctx, lFunc, reEnrollAuthSettings, csr, aps, "reenrollment", validateCert)
	if err != nil {
		return nil, err
	}

	lFunc.Infof("authentication process completed successfully")

	lFunc = lFunc.WithField("step", "DeviceCheck")
	var device *models.Device
	device, err = svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: csr.Subject.CommonName,
	})
	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			lFunc.Debugf("device doesn't exist")
			return nil, err
		default:
			lFunc.Errorf("could not get device: %s", err)
			return nil, err
		}
	} else {
		lFunc.Debugf("device found")
	}

	lFunc = lFunc.WithField("step", "CSRCheck")
	currentDeviceCertSN := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
	currentDeviceCert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: currentDeviceCertSN,
	})
	if err != nil {
		lFunc.Errorf("could not get device certificate '%s' from CA service: %s", currentDeviceCertSN, err)
		return nil, fmt.Errorf("could not get device certificate")
	}

	lFunc.Debugf("device %s ActiveVersion=%d for IdentitySlot is certificate with SN=%s", device.ID, device.IdentitySlot.ActiveVersion, currentDeviceCert.SerialNumber)

	lFunc.Debugf("checking CSR has same RawSubject as the previous enrollment at byte level. DeviceID=%s ActiveVersion=%d", device.ID, device.IdentitySlot.ActiveVersion)
	//Compare CRT & CSR Subject bytes
	if slices.Compare(currentDeviceCert.Certificate.RawSubject, csr.RawSubject) != 0 {
		lFunc.Tracef("current device certificate raw subject (len=%d):\n%v", len(currentDeviceCert.Certificate.RawSubject), currentDeviceCert.Certificate.RawSubject)
		lFunc.Tracef("incoming csr raw subject (len=%d):\n%v", len(csr.RawSubject), csr.RawSubject)
		lFunc.Warnf("incoming CSR for device %s has different RawSubject compared with previous enrollment with ActiveVersion=%d. Will try shallow comparison", device.ID, device.IdentitySlot.ActiveVersion)

		type subjectComp struct {
			claim    string
			crtClaim string
			csrClaim string
		}

		crtSub := currentDeviceCert.Certificate.Subject
		csrSub := csr.Subject
		pairsToCompare := []subjectComp{
			{claim: "CommonName", crtClaim: crtSub.CommonName, csrClaim: csrSub.CommonName},
			{claim: "OrganizationalUnit", crtClaim: strings.Join(crtSub.OrganizationalUnit, ","), csrClaim: strings.Join(csrSub.OrganizationalUnit, ",")},
			{claim: "Organization", crtClaim: strings.Join(crtSub.Organization, ","), csrClaim: strings.Join(csrSub.Organization, ",")},
			{claim: "Locality", crtClaim: strings.Join(crtSub.Locality, ","), csrClaim: strings.Join(csrSub.Locality, ",")},
			{claim: "Province", crtClaim: strings.Join(crtSub.Province, ","), csrClaim: strings.Join(csrSub.Province, ",")},
			{claim: "Country", crtClaim: strings.Join(crtSub.Country, ","), csrClaim: strings.Join(csrSub.Country, ",")},
		}
		for _, pair2Comp := range pairsToCompare {
			if pair2Comp.crtClaim != pair2Comp.csrClaim {
				lFunc.Errorf("current device certificate and csr differ in claim %s. crt got '%s' while csr got '%s'", pair2Comp.claim, pair2Comp.crtClaim, pair2Comp.csrClaim)
				return nil, fmt.Errorf("invalid RawSubject bytes")
			}
		}

	}

	if enrollSettings.VerifyCSRSignature {
		err = checkCSRSignature(lFunc, csr, "reenrollment")
		if err != nil {
			return nil, fmt.Errorf("invalid CSR signature")
		}
	} else {
		lFunc.Warn("DMS is configured with no CSR signature verification, allowing reenrollment")
	}

	now := time.Now()
	lFunc.Debugf("checking if DMS allows enrollment at current delta for device %s", device.ID)

	comparisonTimeThreshold := currentDeviceCert.Certificate.NotAfter.Add(-time.Duration(dms.Settings.ReEnrollmentSettings.ReEnrollmentDelta))
	lFunc.Debugf(
		"current device certificate expires at %s (%s duration). DMS allows reenrolling %s. Reenroll window opens %s. (delta=%s)",
		currentDeviceCert.Certificate.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00"),
		models.TimeDuration(currentDeviceCert.Certificate.NotAfter.Sub(now)).String(),
		reEnrollSettings.ReEnrollmentDelta.String(),
		comparisonTimeThreshold.UTC().Format("2006-01-02T15:04:05Z07:00"),
		models.TimeDuration(now.Sub(comparisonTimeThreshold)).String(),
	)

	//Check if current cert is REVOKED
	if currentDeviceCert.Status == models.StatusRevoked {
		lFunc.Errorf("aborting reenrollment as certificate %s is revoked with status code %s", currentDeviceCertSN, currentDeviceCert.RevocationReason)
		return nil, fmt.Errorf("revoked certificate")
	}

	//Check if Not in DMS ReEnroll Window
	if comparisonTimeThreshold.After(now) {
		lFunc.Errorf("aborting reenrollment. Device has a valid certificate but DMS reenrollment window does not allow reenrolling with %s delta. Update DMS or wait until the reenrollment window is open", models.TimeDuration(now.Sub(comparisonTimeThreshold)).String())
		return nil, fmt.Errorf("invalid reenroll window")
	}

	lFunc = lFunc.WithField("step", "Signature")
	lFunc.Infof("starting signature process")

	issuanceProfile, err := svc.resolveIssuanceProfile(ctx, lFunc, dms, enrollSettings.EnrollmentCA)
	if err != nil {
		return nil, err
	}

	lFunc.Infof("requesting certificate signature")
	crt, err := svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
		CAID:            enrollSettings.EnrollmentCA,
		CertRequest:     (*models.X509CertificateRequest)(csr),
		IssuanceProfile: issuanceProfile,
	})
	if err != nil {
		lFunc.Errorf("could not issue certificate for device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	//detach certificate from meta
	_, err = svc.caClient.UpdateCertificateMetadata(ctx, services.UpdateCertificateMetadataInput{
		SerialNumber: currentDeviceCertSN,
		Patches: chelpers.NewPatchBuilder().
			Remove(chelpers.JSONPointerBuilder(models.DMSAttachedToDeviceKey)).
			Remove(chelpers.JSONPointerBuilder(models.CAMetadataMonitoringExpirationDeltasKey)).
			Build(),
	})
	if err != nil {
		lFunc.Errorf("could not update superseded certificate metadata %s: %s", currentDeviceCert.SerialNumber, err)
		return nil, err
	}

	//revoke superseded cert if active. Don't try revoking expired or already revoked since is not a valid transition for the CA service.
	if currentDeviceCert.Status == models.StatusActive {
		if reEnrollSettings.RevokeOnReEnrollment {
			lFunc.Infof("revoking superseded certificate %s", currentDeviceCertSN)
			_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
				SerialNumber:     currentDeviceCertSN,
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.Superseded,
			})
			if err != nil {
				lFunc.Errorf("could not update superseded certificate status to revoked %s: %s", currentDeviceCert.SerialNumber, err)
				return nil, err
			}
		} else {
			lFunc.Infof("DMS %s is configured to not revoke superseded certificate %s. Skipping revocation", dms.ID, currentDeviceCertSN)
		}
	}

	lFunc.Infof("assigning certificate to device")
	_, err = svc.service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                models.DeviceEventTypeRenewed,
	})
	if err != nil {
		lFunc.Errorf("could not assign certificate to device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	lFunc.Infof("certificate signing process completed successfully")

	lFunc = lFunc.WithField("step", "Done")
	lFunc.Infof("reenrollment process completed successfully")

	return (*x509.Certificate)(crt.Certificate), nil
}

func checkCSRSignature(lFunc *logrus.Entry, csr *x509.CertificateRequest, operation string) error {

	lFunc.Info("checking CSR signature")
	if err := csr.CheckSignature(); err != nil {
		lFunc.Errorf("aborting %s. Invalid CSR signature: %v", operation, err)
		return err
	}
	lFunc.Info("Valid CSR signature")

	return nil
}

func (svc DMSManagerServiceBackend) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, any, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	var privKey any
	var err error

	dms, err := svc.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		return nil, nil, err
	}

	if !dms.Settings.ServerKeyGen.Enabled {
		lFunc.Errorf("server key generation not enabled for DMS: %s", aps)
		return nil, nil, fmt.Errorf("server key generation not enabled")
	}

	keyType := dms.Settings.ServerKeyGen.Key.Type
	keySize := dms.Settings.ServerKeyGen.Key.Bits

	//remove signature algorithm from csr
	csr.SignatureAlgorithm = x509.UnknownSignatureAlgorithm

	switch x509.PublicKeyAlgorithm(keyType) {
	case x509.RSA:
		entropy := software.NewLamassuEntropy(ctx)

		privKey, err = rsa.GenerateKey(entropy, keySize)
		if err != nil {
			return nil, nil, err
		}
	case x509.ECDSA:
		var curve elliptic.Curve
		switch keySize {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			lFunc.Warnf("invalid key size of %d for ECDSA. Defaulting to 256 curve", keySize)
			curve = elliptic.P256()
		}

		entropy := software.NewLamassuEntropy(ctx)

		privKey, err = ecdsa.GenerateKey(curve, entropy)
		if err != nil {
			lFunc.Errorf("could not generate ecdsa key: %s", err)
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unsupported key type %s", keyType)
	}

	entropy := software.NewLamassuEntropy(ctx)

	newCsrBytes, err := x509.CreateCertificateRequest(entropy, csr, privKey)
	if err != nil {
		lFunc.Errorf("could not generate new csr: %s", err)
		return nil, nil, err
	}

	newCsr, err := x509.ParseCertificateRequest(newCsrBytes)
	if err != nil {
		lFunc.Errorf("could not parse newly generated CSR: %s", err)
		return nil, nil, err
	}

	crt, err := svc.Enroll(ctx, newCsr, aps)
	if err != nil {
		lFunc.Errorf("could not enroll: %s", err)
		return nil, nil, err
	}

	return crt, privKey, nil
}

type revocationStatus int

const (
	revocationStatusGood revocationStatus = iota
	revocationStatusRevoked
	// revocationStatusNoSource means the certificate is not managed by Lamassu and carries no OCSP or CRL
	// endpoint, so there is nothing to check its revocation status against.
	revocationStatusNoSource
)

const (
	// revocationClockSkew tolerates small clock differences with OCSP responders and CRL issuers.
	revocationClockSkew = 5 * time.Minute
	// revocationMaxAgeWithoutNextUpdate bounds the age of an OCSP response or CRL that omits nextUpdate, so an old
	// "not revoked" answer cannot be replayed indefinitely.
	revocationMaxAgeWithoutNextUpdate = 24 * time.Hour
)

// checkRevocationFreshness returns an error unless now falls within the validity window of an OCSP response or CRL.
// Callers only apply it to "not revoked" answers; a "revoked" answer is honored regardless of its age.
func checkRevocationFreshness(thisUpdate, nextUpdate, now time.Time) error {
	if thisUpdate.IsZero() {
		return fmt.Errorf("missing thisUpdate")
	}

	if thisUpdate.After(now.Add(revocationClockSkew)) {
		return fmt.Errorf("thisUpdate %s is in the future", thisUpdate.UTC().Format(time.RFC3339))
	}

	if nextUpdate.IsZero() {
		if now.Sub(thisUpdate) > revocationMaxAgeWithoutNextUpdate {
			return fmt.Errorf("no nextUpdate and thisUpdate %s is older than %s", thisUpdate.UTC().Format(time.RFC3339), revocationMaxAgeWithoutNextUpdate)
		}
		return nil
	}

	if now.After(nextUpdate.Add(revocationClockSkew)) {
		return fmt.Errorf("nextUpdate %s has passed", nextUpdate.UTC().Format(time.RFC3339))
	}

	return nil
}

// checkCertificateRevocation determines the revocation status of cert, whose direct issuer is issuer.
// If the certificate is managed by Lamassu its stored status is used. Otherwise the OCSP servers and then the CRL
// distribution points listed in the certificate are consulted. An error is returned when the certificate lists
// revocation endpoints but none of them produced a valid, fresh and conclusive answer.
func (svc DMSManagerServiceBackend) checkCertificateRevocation(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate) (revocationStatus, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	clientSN := helpers.SerialNumberToHexString(cert.SerialNumber)
	lmsCrt, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: clientSN,
	})
	if err != nil && err != errs.ErrCertificateNotFound {
		lFunc.Errorf("got unexpected error while searching certificate %s in Lamassu: %s", clientSN, err)
		return revocationStatusRevoked, err
	}

	if err == nil {
		// Serial numbers are only unique per issuer: make sure the stored certificate is the presented one.
		if lmsCrt.Certificate != nil && bytes.Equal(lmsCrt.Certificate.Raw, cert.Raw) {
			if lmsCrt.Status == models.StatusRevoked {
				lFunc.Errorf("client certificate %s is revoked", clientSN)
				return revocationStatusRevoked, nil
			}
			return revocationStatusGood, nil
		}
		lFunc.Warnf("certificate with serial number %s stored in Lamassu differs from the presented one. Checking revocation using the presented certificate's OCSP/CRL endpoints", clientSN)
	}

	if len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 {
		lFunc.Warnf("certificate %s is not managed by Lamassu and has no OCSP/CRL endpoints", clientSN)
		return revocationStatusNoSource, nil
	}

	now := time.Now()

	for _, ocspInstance := range cert.OCSPServer {
		ocspResp, err := external_clients.GetOCSPResponsePost(ocspInstance, cert, issuer, nil, true)
		if err != nil {
			lFunc.Warnf("could not get or validate ocsp response from server %s for certificate %s: %s. Checking with next revocation source", ocspInstance, clientSN, err)
			continue
		}

		if ocspResp.SerialNumber == nil || ocspResp.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			lFunc.Warnf("ocsp response from server %s does not match certificate %s. Checking with next revocation source", ocspInstance, clientSN)
			continue
		}

		if ocspResp.Status == ocsp.Revoked {
			lFunc.Warnf("certificate was revoked at %s with %s revocation reason", ocspResp.RevokedAt.String(), models.RevocationReasonMap[ocspResp.RevocationReason])
			return revocationStatusRevoked, nil
		}

		if err := checkRevocationFreshness(ocspResp.ThisUpdate, ocspResp.NextUpdate, now); err != nil {
			lFunc.Warnf("ocsp response from server %s for certificate %s is not fresh: %s. Checking with next revocation source", ocspInstance, clientSN, err)
			continue
		}

		if ocspResp.Status != ocsp.Good {
			lFunc.Warnf("ocsp server %s reports unknown status for certificate %s. Checking with next revocation source", ocspInstance, clientSN)
			continue
		}

		lFunc.Infof("ocsp server %s reports certificate %s as not revoked", ocspInstance, clientSN)
		return revocationStatusGood, nil
	}

	crlChecked := false
	for _, crlDP := range cert.CRLDistributionPoints {
		crl, err := external_clients.GetCRLResponse(crlDP, issuer, nil, true)
		if err != nil {
			lFunc.Warnf("could not get or validate crl from %s for certificate %s: %s. Checking with next revocation source", crlDP, clientSN, err)
			continue
		}

		idxClientCrt := slices.IndexFunc(crl.RevokedCertificateEntries, func(entry x509.RevocationListEntry) bool {
			return entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0
		})
		if idxClientCrt >= 0 {
			entry := crl.RevokedCertificateEntries[idxClientCrt]
			lFunc.Warnf("certificate was revoked at %s with %s revocation reason", entry.RevocationTime.String(), models.RevocationReasonMap[entry.ReasonCode])
			return revocationStatusRevoked, nil
		}

		if err := checkRevocationFreshness(crl.ThisUpdate, crl.NextUpdate, now); err != nil {
			lFunc.Warnf("crl from %s is not fresh: %s. Checking with next revocation source", crlDP, err)
			continue
		}

		lFunc.Infof("certificate not revoked. Client certificate %s not in CRL %s", clientSN, crlDP)
		crlChecked = true
		//don't return, check other CRLs
	}

	if crlChecked {
		return revocationStatusGood, nil
	}

	return revocationStatusRevoked, fmt.Errorf("none of the OCSP/CRL endpoints of certificate %s returned a valid, fresh and conclusive response", clientSN)
}

func (svc DMSManagerServiceBackend) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	crt, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.CertificateSerialNumber,
	})
	if err != nil {
		return nil, err
	}

	device, err := svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: input.DeviceID,
	})
	if err != nil {
		return nil, err
	}

	dms, err := svc.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: device.DMSOwner,
	})
	if err != nil {
		return nil, err
	}

	expirationDeltas := models.CAMetadataMonitoringExpirationDeltas{
		{
			Delta:     dms.Settings.ReEnrollmentSettings.PreventiveReEnrollmentDelta,
			Name:      "Preventive",
			Triggered: false,
		},
		{
			Delta:     dms.Settings.ReEnrollmentSettings.CriticalReEnrollmentDelta,
			Name:      "Critical",
			Triggered: false,
		},
	}
	caAttachedToDevice := models.CAAttachedToDevice{
		AuthorizedBy: struct {
			RAID string "json:\"ra_id\""
		}{RAID: dms.ID},
		DeviceID: device.ID,
	}

	crt, err = svc.caClient.UpdateCertificateMetadata(ctx, services.UpdateCertificateMetadataInput{
		SerialNumber: crt.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(models.CAMetadataMonitoringExpirationDeltasKey), expirationDeltas).
			Add(chelpers.JSONPointerBuilder(models.DMSAttachedToDeviceKey), caAttachedToDevice).
			Build(),
	})
	if err != nil {
		lFunc.Errorf("could not update certificate metadata with monitoring deltas for certificate with sn '%s': %s", crt.SerialNumber, err)
		return nil, err
	}

	idSlot := device.IdentitySlot
	eventType := models.DeviceEventTypeProvisioned
	eventDescription := ""
	if idSlot == nil {
		idSlot = &models.Slot[string]{
			Status:         models.SlotActive,
			ActiveVersion:  0,
			SecretType:     models.X509SlotProfileType,
			ExpirationDate: &crt.ValidTo,
			Secrets: map[int]string{
				0: crt.SerialNumber,
			},
			Events: map[time.Time]models.DeviceEvent{},
		}
	} else {
		idSlot.ActiveVersion = idSlot.ActiveVersion + 1
		idSlot.Status = models.SlotActive
		idSlot.ExpirationDate = &crt.ValidTo
		idSlot.Secrets[idSlot.ActiveVersion] = crt.SerialNumber
		eventType = input.BindMode
		eventDescription = fmt.Sprintf("New Active Version set to %d", idSlot.ActiveVersion)
	}
	_, err = svc.deviceManagerCli.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
		ID:   crt.Subject.CommonName,
		Slot: *idSlot,
	})
	if err != nil {
		lFunc.Errorf("could not update device '%s' identity slot. Aborting enrollment process: %s", device.ID, err)
		return nil, err
	}

	_, err = svc.deviceManagerCli.CreateDeviceEvent(ctx, services.CreateDeviceEventInput{
		DeviceID:    crt.Subject.CommonName,
		Timestamp:   time.Now(),
		Type:        eventType,
		Description: eventDescription,
		Source:      models.DMSManagerSource,
	})
	if err != nil {
		lFunc.Errorf("could not create device event for device '%s': %s", device.ID, err)
		return nil, err
	}

	return &models.BindIdentityToDeviceOutput{
		Certificate: crt,
		DMS:         dms,
		Device:      device,
	}, nil
}

func (svc DMSManagerServiceBackend) resolveIssuanceProfile(ctx context.Context, lFunc *logrus.Entry, dms *models.DMS, enrollmentCA string) (*models.IssuanceProfile, error) {
	issuanceProfile := dms.Settings.IssuanceProfile
	if dms.Settings.IssuanceProfileID != "" {
		profile, err := svc.caClient.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{
			ProfileID: dms.Settings.IssuanceProfileID,
		})
		if err != nil {
			lFunc.Errorf("could not get issuance profile with ID=%s: %s", dms.Settings.IssuanceProfileID, err)
			return nil, err
		}
		issuanceProfile = profile
	}

	if issuanceProfile == nil {
		lFunc.Warnf("no issuance profile configured for DMS. using default profile from CA")
		profile, err := svc.getProfileForCA(ctx, enrollmentCA)
		if err != nil {
			lFunc.Errorf("could not get default issuance profile from CA: %s", err)
			return nil, err
		}
		issuanceProfile = profile
	}

	return issuanceProfile, nil
}

func (svc DMSManagerServiceBackend) getProfileForCA(ctx context.Context, caID string) (*models.IssuanceProfile, error) {
	ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: caID,
	})
	if err != nil {
		return nil, err
	}

	profile, err := svc.caClient.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{
		ProfileID: ca.ProfileID,
	})
	if err != nil {
		return nil, err
	}

	return profile, nil
}
