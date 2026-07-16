package services

import (
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
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	webhookclient "github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers/webhook-client"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	external_clients "github.com/lamassuiot/lamassuiot/sdk/v3/external"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

var dmsValidate = validator.New()

type DMSManagerMiddleware func(services.DMSManagerService) services.DMSManagerService

type DMSManagerServiceBackend struct {
	service          services.DMSManagerService
	dmsStorage       storage.DMSRepo
	cmptxStorage     storage.CMPTransactionRepo
	cmpWFXReporter   cmpwfx.CMPReporter
	deviceManagerCli services.DeviceManagerService
	kmsClient        services.KMSService
	caClient         services.CAService
	logger           *logrus.Entry
	downstreamCert   *x509.Certificate // included as system CA in EST CACerts responses
}

type DMSManagerBuilder struct {
	Logger                *logrus.Entry
	DevManagerCli         services.DeviceManagerService
	CAClient              services.CAService
	KMSClient             services.KMSService
	DMSStorage            storage.DMSRepo
	CMPTransactionStorage storage.CMPTransactionRepo
	CMPWFXReporter        cmpwfx.CMPReporter
	DownstreamCertificate *x509.Certificate
}

func NewDMSManagerService(builder DMSManagerBuilder) services.DMSManagerService {
	svc := &DMSManagerServiceBackend{
		dmsStorage:       builder.DMSStorage,
		cmptxStorage:     builder.CMPTransactionStorage,
		cmpWFXReporter:   builder.CMPWFXReporter,
		caClient:         builder.CAClient,
		deviceManagerCli: builder.DevManagerCli,
		logger:           builder.Logger,
		downstreamCert:   builder.DownstreamCertificate,
		kmsClient:        builder.KMSClient,
	}

	svc.service = svc

	return svc
}

func (svc *DMSManagerServiceBackend) SetService(service services.DMSManagerService) {
	svc.service = service
}

// ensureDeviceRegistered applies JITP registration logic given a device that may or may not exist.
// If device is nil and the DMS is configured with JITP, the device is created.
// If device is nil and JITP is disabled, an error is returned.
// Returns the (possibly newly created) device.
func (svc DMSManagerServiceBackend) ensureDeviceRegistered(ctx context.Context, lFunc *logrus.Entry, enrollSettings models.EnrollmentSettings, dmsID string, deviceID string, device *models.Device) (*models.Device, error) {
	if enrollSettings.RegistrationMode == models.JITP {
		if device == nil {
			lFunc.Debugf("DMS is configured with JustInTime registration. will create device with ID %s", deviceID)
			var err error
			device, err = svc.deviceManagerCli.CreateDevice(ctx, services.CreateDeviceInput{
				ID:        deviceID,
				Alias:     deviceID,
				Tags:      enrollSettings.DeviceProvisionProfile.Tags,
				Metadata:  enrollSettings.DeviceProvisionProfile.Metadata,
				Icon:      enrollSettings.DeviceProvisionProfile.Icon,
				IconColor: enrollSettings.DeviceProvisionProfile.IconColor,
				DMSID:     dmsID,
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

	return device, nil
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

	if err := normalizeProtocolSettings(&input.Settings); err != nil {
		lFunc.Errorf("invalid enrollment protocol for DMS '%s': %s", input.ID, err)
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
	lFunc.Debugf("checking if DMS '%s' exists", input.DMS.ID)
	exists, dms, err := svc.dmsStorage.SelectExists(ctx, input.DMS.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if DMS '%s' exists in storage engine: %s", input.DMS.ID, err)
		return nil, err
	} else if !exists {
		lFunc.Errorf("DMS '%s' does not exist in storage engine", input.DMS.ID)
		return nil, errs.ErrDMSNotFound
	}

	if err := normalizeProtocolSettings(&input.DMS.Settings); err != nil {
		lFunc.Errorf("invalid enrollment protocol for DMS '%s': %s", input.DMS.ID, err)
		return nil, err
	}

	dms.Metadata = input.DMS.Metadata
	dms.Name = input.DMS.Name
	dms.Settings = input.DMS.Settings

	lFunc.Debugf("updating DMS %s", input.DMS.ID)
	return svc.dmsStorage.Update(ctx, dms)
}

// normalizeProtocolSettings enforces that a DMS uses exactly one enrollment
// protocol (EST or CMP) and zeroes out the settings struct of the protocol
// that is NOT selected. This is intentional: persisting stale config for an
// unused protocol is misleading in the UI and ambiguous to operators. The
// top-level EnrollmentSettings.EnrollmentCA is the single source of truth for
// the issuing CA — there are no protocol-specific overrides.
func normalizeProtocolSettings(settings *models.DMSSettings) error {
	switch settings.EnrollmentSettings.EnrollmentProtocol {
	case models.EST:
		settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483 = models.EnrollmentOptionsLWCRFC9483{}
	case models.CMP:
		settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030 = models.EnrollmentOptionsESTRFC7030{}
	default:
		return errs.ErrDMSInvalidProtocol
	}
	return nil
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

// authenticateEnrollment runs a DMS's configured enrollment authentication
// policy. It is the canonical implementation introduced in PR #616 (combined
// Client Certificate + Webhook auth), generalised so EST and CMP share it: the
// caller extracts the presented client credential in its own protocol-specific
// way — EST uses the mTLS transport certificate chain, CMP uses the
// signature-based message-protection signer cert (extraCerts[0], RFC 9483 §3.2)
// — and passes it as clientCerts (leaf first). The auth_mode is authoritative
// and is the single source of truth: selecting CLIENT_CERTIFICATE or the
// combined mode always requires a credential, and for CMP the controller also
// derives its "must be signed at the wire layer" requirement from the same
// auth_mode (no separate enforce_request_protection knob).
// Returns nil when the request is authorized.
func (svc DMSManagerServiceBackend) authenticateEnrollment(
	ctx context.Context,
	lFunc *logrus.Entry,
	auth models.EnrollmentAuthSettings,
	clientCerts []*x509.Certificate,
	csr *x509.CertificateRequest,
	aps string,
	operation string,
) error {
	switch auth.AuthMode {
	case models.EnrollmentAuthModeNoAuth, "NONE", "":
		// "NONE" is the value the dashboard persists for No Auth, and "" is an
		// unset auth mode; both previously fell through EST's permissive default
		// and allowed enrollment. Treat them as NO_AUTH so those DMSs keep
		// working exactly as before.
		lFunc = lFunc.WithField("auth-method", models.EnrollmentAuthModeNoAuth)
		lFunc.Warnf("DMS is configured with NoAuth, allowing %s", operation)
		return nil

	case models.EnrollmentAuthModeClientCertificate:
		lFunc = lFunc.WithField("auth-method", models.EnrollmentAuthModeClientCertificate)
		return svc.validateClientCertificateEnrollment(ctx, lFunc, auth, clientCerts)

	case models.EnrollmentAuthModeExternalWebhook:
		lFunc = lFunc.WithField("auth-method", models.EnrollmentAuthModeExternalWebhook)
		return invokeWebhook(ctx, lFunc, auth.AuthOptionsExternalWebhook, csr, aps, operation)

	case models.EnrollmentAuthModeClientCertificateAndWebhook:
		lFunc = lFunc.WithField("auth-method", models.EnrollmentAuthModeClientCertificateAndWebhook)
		lFunc.Infof("combined auth: starting client certificate validation (step 1/2)")
		if err := svc.validateClientCertificateEnrollment(ctx, lFunc, auth, clientCerts); err != nil {
			return err
		}
		lFunc.Infof("combined auth: client certificate validation passed. Starting webhook validation (step 2/2)")
		if err := invokeWebhook(ctx, lFunc, auth.AuthOptionsExternalWebhook, csr, aps, operation); err != nil {
			return err
		}
		lFunc.Infof("combined auth: both client certificate and webhook validations passed")
		return nil

	default:
		lFunc.Errorf("aborting %s. DMS has no/invalid auth method configured (%q)", operation, auth.AuthMode)
		return errs.ErrDMSAuthModeNotSupported
	}
}

// validateClientCertificateEnrollment validates the presented client
// certificate chain against the DMS's ValidationCAs (honouring AllowExpired and
// ChainLevelValidation) and checks the leaf's revocation status. Selecting
// CLIENT_CERTIFICATE (or the combined mode) means a credential is mandatory —
// auth_mode is authoritative — so a missing client certificate is always fatal,
// regardless of the protocol's wire-level protection flag. Recovered from PR #616.
func (svc DMSManagerServiceBackend) validateClientCertificateEnrollment(
	ctx context.Context,
	lFunc *logrus.Entry,
	auth models.EnrollmentAuthSettings,
	clientCerts []*x509.Certificate,
) error {
	if len(clientCerts) == 0 {
		lFunc.Errorf("aborting enrollment. No client certificate was presented")
		return errs.ErrDMSAuthModeNotSupported
	}

	leafClientCert := clientCerts[0]
	mtlsOpts := auth.AuthOptionsMTLS

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
		if err := helpers.ValidateCertificates((*x509.Certificate)(ca.Certificate.Certificate), clientCerts, !mtlsOpts.AllowExpired); err != nil {
			lFunc.Debugf("invalid validation using CA [%s] with CommonName '%s', SerialNumber '%s'", ca.ID, ca.Certificate.Subject.CommonName, ca.Certificate.SerialNumber)
			continue
		}
		lFunc.Infof("certificate validated. Revocation check will be performed next")
		validationCA = ca
		break
	}

	if validationCA == nil {
		lFunc.WithField("auth-status", "failed").Errorf("aborting enrollment. used certificate not authorized for this DMS")
		return errs.ErrDMSEnrollInvalidCert
	}

	couldCheckRevocation, isRevoked, err := svc.checkCertificateRevocation(ctx, leafClientCert, (*x509.Certificate)(validationCA.Certificate.Certificate))
	if err != nil {
		lFunc.WithField("auth-status", "failed").Errorf("aborting enrollment. error while checking certificate revocation status: %s", err)
		return err
	}
	if !couldCheckRevocation {
		lFunc.Warnf("could not verify certificate revocation status. Assuming certificate as not-revoked")
		return nil
	}
	if isRevoked {
		lFunc.WithField("auth-status", "failed").Errorf("aborting enrollment. certificate is revoked")
		return fmt.Errorf("certificate is revoked")
	}
	lFunc.Infof("certificate is not revoked")
	return nil
}

// invokeWebhook delegates the enrollment authorization decision to the DMS's
// configured external webhook, posting the CSR, APS, device CN, and the incoming
// HTTP request metadata, and enforcing a call deadline. Recovered from PR #616.
func invokeWebhook(ctx context.Context, lFunc *logrus.Entry, webhookConf models.WebhookCall, csr *x509.CertificateRequest, aps string, operation string) error {
	lFunc = lFunc.WithField("auth-status", "verifying")
	lFunc.Infof("verifying %s using external webhook: %s. Calling webhook %s", operation, webhookConf.Name, webhookConf.Url)

	webhookRequestBodyHeaders := make(map[string]string)
	requestURL := ""
	if httpReq, ok := ctx.Value(core.LamassuContextKeyHTTPRequest).(*http.Request); ok && httpReq != nil {
		for key, values := range httpReq.Header {
			if len(values) > 0 {
				webhookRequestBodyHeaders[key] = values[0]
			}
		}
		requestURL = httpReq.URL.String()
	}

	pemCsr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	webhookRequestBody := map[string]any{
		"csr":       base64.StdEncoding.EncodeToString(pemCsr),
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
	type webhookInvocationResult struct {
		resp *webhookResponse
		err  error
	}

	webhookTimeout := 10 * time.Second
	if webhookConf.Config.CallTimeout > 0 {
		webhookTimeout = time.Duration(webhookConf.Config.CallTimeout)
	}
	webhookCtx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()

	webhookResultCh := make(chan webhookInvocationResult, 1)
	go func() {
		resp, err := webhookclient.InvokeJSONWebhook[webhookResponse](lFunc, webhookConf, webhookRequestBody)
		webhookResultCh <- webhookInvocationResult{resp: resp, err: err}
	}()

	select {
	case <-webhookCtx.Done():
		lFunc.WithField("auth-status", "failed").Errorf("aborting %s. external webhook authorization did not complete before deadline: %s", operation, webhookCtx.Err())
		return fmt.Errorf("external webhook authorization timed out or was canceled: %w", webhookCtx.Err())
	case result := <-webhookResultCh:
		if result.err != nil {
			lFunc.WithField("auth-status", "failed").Errorf("aborting %s. got error while calling external webhook: %s", operation, result.err)
			return fmt.Errorf("error while calling external webhook: %s", result.err)
		}
		if result.resp == nil {
			lFunc.WithField("auth-status", "failed").Errorf("aborting %s. external webhook didn't return a response", operation)
			return fmt.Errorf("external webhook didn't return a response")
		}
		if !result.resp.Authorized {
			lFunc.WithField("auth-status", "failed").Errorf("aborting %s. external webhook denied %s", operation, operation)
			return fmt.Errorf("external webhook denied %s", operation)
		}
	}

	lFunc.WithField("auth-uri", webhookConf.Name).Infof("webhook authorized %s", operation)
	return nil
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

	if enrollSettings.EnrollmentProtocol != models.EST && enrollSettings.EnrollmentProtocol != models.CMP {
		lFunc.Errorf("aborting enrollment. DMS enrollment protocol not supported (got %s)", enrollSettings.EnrollmentProtocol)
		return nil, errs.ErrDMSOnlyEST
	}

	estAuthOptions := enrollSettings.EnrollmentOptionsESTRFC7030

	lFunc = lFunc.WithField("step", "Authenticating")
	lFunc.Infof("starting authentication process")
	// EST presents the client identity as the mTLS transport certificate chain
	// (leaf first), stashed by the identity middleware as []*x509.Certificate.
	// All four modes (NO_AUTH, CLIENT_CERTIFICATE, EXTERNAL_WEBHOOK, and both)
	// are handled by the shared authenticator.
	clientCerts, _ := ctx.Value(string(identityextractors.IdentityExtractorClientCertificate)).([]*x509.Certificate)
	if err := svc.authenticateEnrollment(ctx, lFunc, estAuthOptions.AuthSettings(), clientCerts, csr, aps, "enrollment"); err != nil {
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

	device, err = svc.ensureDeviceRegistered(ctx, lFunc, enrollSettings, dms.ID, csr.Subject.CommonName, device)
	if err != nil {
		return nil, err
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
	if enrollSettings.EnrollmentProtocol != models.EST && enrollSettings.EnrollmentProtocol != models.CMP {
		lFunc.Errorf("aborting reenrollment. DMS enrollment protocol not supported (got %s)", enrollSettings.EnrollmentProtocol)
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
	estAuthOpts := reEnrollSettings.ReEnrollmentOptionsESTRFC7030

	switch estAuthOpts.AuthMode {
	case models.EnrollmentAuthModeClientCertificate, models.EnrollmentAuthModeClientCertificateAndWebhook:
		lFunc = lFunc.WithField("auth-method", estAuthOpts.AuthMode)
		clientCerts, _ := ctx.Value(string(identityextractors.IdentityExtractorClientCertificate)).([]*x509.Certificate)
		if len(clientCerts) == 0 {
			lFunc.Errorf("aborting reenrollment. No client certificate was presented")
			return nil, errs.ErrDMSAuthModeNotSupported
		}
		clientCert := clientCerts[0]

		lFunc = lFunc.WithField("auth-status", "verifying")
		lFunc = lFunc.WithField("auth-uri", fmt.Sprintf("CN=%s, SN=%s, Issuer=%s", clientCert.Subject.CommonName, helpers.SerialNumberToHexString(clientCert.SerialNumber), clientCert.Issuer.CommonName))
		lFunc.Debugf("presented client certificate")

		validCertificate := false
		var validationCA *x509.Certificate

		//check if certificate is a certificate issued by Enroll CA
		lFunc.Debugf("validating client certificate using EST Enrollment CA witch has ID=%s CN=%s SN=%s", enrollCAID, enrollCA.Certificate.Subject.CommonName, enrollCA.Certificate.SerialNumber)
		err = helpers.ValidateCertificate((*x509.Certificate)(enrollCA.Certificate.Certificate), clientCert, false)
		if err != nil {
			lFunc.Warnf("invalid validation using enroll CA: %s", err)
		} else {
			lFunc.Infof("certificate validated. Revocation and Expiration (if needed) check will be performed next")
			validationCA = (*x509.Certificate)(enrollCA.Certificate.Certificate)
			validCertificate = true
		}

		//try secondary validation with additional CAs
		if !validCertificate {

			aValCAsCtr := len(reEnrollSettings.AdditionalValidationCAs)
			lFunc.Debugf("could not validate client certificate using enroll CA. Will try validating using Additional Validation CAs")
			lFunc.Debugf("DMS has %d additional validation CAs", aValCAsCtr)

			//check if certificate is a certificate issued by Extra Val CAs
			for idx, caID := range reEnrollSettings.AdditionalValidationCAs {
				lFunc.Debugf("[%d/%d] obtaining validation with ID %s", idx, aValCAsCtr, caID)
				ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
				if err != nil {
					lFunc.Warnf("[%d/%d] could not obtain lamassu CA with ID %s. Skipping to next validation CA: %s", idx, aValCAsCtr, caID, err)
					continue
				}

				err = helpers.ValidateCertificate((*x509.Certificate)(ca.Certificate.Certificate), clientCert, false)
				if err != nil {
					lFunc.Debugf("[%d/%d] invalid validation using CA [%s] with CommonName '%s', SerialNumber '%s'", idx, aValCAsCtr, ca.ID, ca.Certificate.Subject.CommonName, ca.Certificate.SerialNumber)
				} else {
					lFunc.Debugf("[%d/%d] OK validation using CA [%s] with CommonName '%s', SerialNumber '%s'", idx, aValCAsCtr, ca.ID, ca.Certificate.Subject.CommonName, ca.Certificate.SerialNumber)
					validCertificate = true
					break
				}
			}
		}

		//abort reenrollment process. No CA signed the client certificate
		if !validCertificate {
			caAki := ""
			if len(clientCert.AuthorityKeyId) > 0 {
				caAki = string(clientCert.AuthorityKeyId)
			}

			lFunc = lFunc.WithField("auth-status", "failed")
			lFunc.Errorf("aborting reenrollment process. Unknown CA:\nCN: %s\nAKI:%s", clientCert.Issuer.CommonName, caAki)
			return nil, errs.ErrDMSEnrollInvalidCert
		}

		if reEnrollSettings.EnableExpiredRenewal {
			lFunc.Warnf("DMS configured to allow reenrollment with expired certificates")
		} else {
			lFunc.Info("DMS configured to NOT allow reenrollment with expired certificates")
		}

		//Check if EXPIRED
		{
			now := time.Now()
			if now.After(clientCert.NotAfter) {
				if reEnrollSettings.EnableExpiredRenewal {
					lFunc.Warnf("presented an expired certificate: %s", now.Sub(clientCert.NotBefore))
				} else {
					lFunc = lFunc.WithField("auth-status", "failed")
					lFunc.Errorf("aborting reenrollment. device has a valid but expired certificate")
					return nil, fmt.Errorf("expired certificate")
				}
			}
		}

		//checks against Lamassu, external OCSP or CRL
		lFunc.Infof("checking certificate revocation status")
		couldCheckRevocation, isRevoked, err := svc.checkCertificateRevocation(ctx, clientCert, (*x509.Certificate)(validationCA))
		if err != nil {
			lFunc = lFunc.WithField("auth-status", "failed")
			lFunc.Errorf("aborting reenrollment. could not check certificate revocation status: %s", err)
			lFunc.Errorf("error while checking certificate revocation status: %s", err)
			return nil, err
		}

		if couldCheckRevocation {
			if isRevoked {
				lFunc = lFunc.WithField("auth-status", "failed")
				lFunc.Errorf("aborting enrollment. certificate is revoked")
				return nil, fmt.Errorf("certificate is revoked")
			}
			lFunc.Infof("certificate is not revoked")
		} else {
			lFunc.Infof("could not verify certificate expiration. Assuming certificate as not-revoked")
		}

		if estAuthOpts.AuthMode == models.EnrollmentAuthModeClientCertificateAndWebhook {
			lFunc.Infof("combined auth: client certificate validated. Starting webhook validation (step 2/2)")
			if err := invokeWebhook(ctx, lFunc, estAuthOpts.AuthOptionsExternalWebhook, csr, aps, "reenrollment"); err != nil {
				return nil, err
			}
		}

	case models.EnrollmentAuthModeExternalWebhook:
		lFunc = lFunc.WithField("auth-method", models.EnrollmentAuthModeExternalWebhook)
		if err := invokeWebhook(ctx, lFunc, estAuthOpts.AuthOptionsExternalWebhook, csr, aps, "reenrollment"); err != nil {
			return nil, err
		}

	default:
		lFunc.Warnf("allowing reenroll: using NO AUTH mode")
	}

	lFunc = lFunc.WithField("auth-status", "verified")
	lFunc.Infof("certificate verified")

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

// returns if the given certificate COULD BE checked for revocation (true means that it could be checked), and if it is revoked (true) or not (false)
func (svc DMSManagerServiceBackend) checkCertificateRevocation(ctx context.Context, cert *x509.Certificate, validationCA *x509.Certificate) (bool, bool, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	revocationChecked := false
	revoked := true
	clientSN := helpers.SerialNumberToHexString(cert.SerialNumber)
	//check if revoked
	//  If cert is in Lamassu: check status
	//  If cert NOT in Lamassu (i.e. Issued Offline/Outside Lamassu), check if the certificate has CRL/OCSP in presented CRT.
	lmsCrt, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: clientSN,
	})
	if err != nil {
		if err != errs.ErrCertificateNotFound {
			lFunc.Errorf("got unexpected error while searching certificate %s in Lamassu: %s", clientSN, err)
			return false, true, err
		}

		//Not Stored In lamassu. Check if CRL/OCSP
		if len(cert.OCSPServer) > 0 {
			//OCSP first
			for _, ocspInstance := range cert.OCSPServer {
				ocspResp, err := external_clients.GetOCSPResponsePost(ocspInstance, cert, validationCA, nil, true)
				if err != nil {
					lFunc.Warnf("could not get or validate ocsp response from server %s specified in the presented client certificate: %s", err, clientSN)
					lFunc.Warnf("checking with next ocsp server")
					continue
				}

				lFunc.Infof("successfully validated OCSP response with external %s OCSP server. Checking OCSP response status for %s certificate", ocspInstance, clientSN)
				if ocspResp.Status == ocsp.Revoked {
					lFunc.Warnf("certificate was revoked at %s with %s revocation reason", ocspResp.RevokedAt.String(), models.RevocationReasonMap[ocspResp.RevocationReason])
					return true, true, nil
				} else {
					lFunc.Infof("certificate is not revoked")
					return true, false, nil
				}
			}
		}

		if !revocationChecked && len(cert.CRLDistributionPoints) > 0 {
			//Try CRL
			for _, crlDP := range cert.CRLDistributionPoints {
				crl, err := external_clients.GetCRLResponse(crlDP, validationCA, nil, true)
				if err != nil {
					lFunc.Warnf("could not get or validate crl response from server %s specified in the presented client certificate: %s", err, clientSN)
					lFunc.Warnf("checking with next crl server")
					continue
				}

				idxClientCrt := slices.IndexFunc(crl.RevokedCertificateEntries, func(entry x509.RevocationListEntry) bool {
					return entry.SerialNumber == cert.SerialNumber
				})

				if idxClientCrt >= 0 {
					entry := crl.RevokedCertificateEntries[idxClientCrt]
					lFunc.Warnf("certificate was revoked at %s with %s revocation reason", entry.RevocationTime.String(), models.RevocationReasonMap[entry.ReasonCode])
					return true, true, nil
				} else {
					lFunc.Infof("certificate not revoked. Client certificate not in CRL: %s", clientSN)
					revocationChecked = true
					revoked = false
					//don't return, check other CRLs
				}
			}
		}
	} else {
		if lmsCrt.Status == models.StatusRevoked {
			lFunc.Errorf("Client certificate %s is revoked", clientSN)
			return true, true, nil
		} else {
			return true, false, nil
		}
	}

	return revocationChecked, revoked, nil
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
		ID:   device.ID,
		Slot: *idSlot,
	})
	if err != nil {
		lFunc.Errorf("could not update device '%s' identity slot. Aborting enrollment process: %s", device.ID, err)
		return nil, err
	}

	_, err = svc.deviceManagerCli.CreateDeviceEvent(ctx, services.CreateDeviceEventInput{
		DeviceID:    device.ID,
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
