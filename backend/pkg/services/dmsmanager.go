package services

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	external_clients "github.com/lamassuiot/lamassuiot/sdk/v3/external"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

var dmsValidate = validator.New()

// cmpCertConfDefaultTTL is the fallback certConf window applied to a phased
// transaction once it is approved (moves PENDING → ISSUED) when the DMS does
// not configure ConfirmationTimeout. Mirrors the controller's cmpTxTTL — the
// post-approval row behaves like any other issued-awaiting-confirmation row.
const cmpCertConfDefaultTTL = 5 * time.Minute

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

// GetCMPTransactionRepo exposes the persistent CMP transaction store so that
// the HTTP controller layer can access it without polluting the DMSManagerService
// interface.  Controllers type-assert the service to CMPTransactionStorer.
func (svc *DMSManagerServiceBackend) GetCMPTransactionRepo() storage.CMPTransactionRepo {
	return svc.cmptxStorage
}

// GetCMPWFXReporter exposes the optional WFX reporter used to mirror CMP
// transaction state transitions into WFX jobs.
func (svc *DMSManagerServiceBackend) GetCMPWFXReporter() cmpwfx.CMPReporter {
	return svc.cmpWFXReporter
}

// GetCMPTransactionsByDMS lists CMP transactions belonging to the given DMS,
// honouring the standard pagination/sort/filter parameters. It verifies the
// DMS exists first so callers get a 404 when targeting a bogus ID rather than
// an empty list that could hide a typo. Both in-flight and stale rows are
// included; expiry filtering is intentionally NOT applied at this layer
// (operators want stale rows visible for diagnosis).
func (svc DMSManagerServiceBackend) GetCMPTransactionsByDMS(ctx context.Context, input services.GetCMPTransactionsByDMSInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	exists, _, err := svc.dmsStorage.SelectExists(ctx, input.DMSID)
	if err != nil {
		lFunc.Errorf("could not check DMS %s exists: %s", input.DMSID, err)
		return "", err
	}
	if !exists {
		return "", errs.ErrDMSNotFound
	}

	return svc.cmptxStorage.SelectAllByDMS(ctx, input.DMSID, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters)
}

// ApproveCMPTransaction releases a PENDING phased-workflow transaction: it
// issues the certificate from the stored CSR, flips the row to ISSUED (so the
// EE can fetch it via pollReq), and mirrors the AwaitingApproval → Responded →
// AwaitingCertConf transitions into WFX. On issuance failure the row is moved
// to ISSUE_FAILED so pollReq can surface the reason.
func (svc DMSManagerServiceBackend) ApproveCMPTransaction(ctx context.Context, input services.ApproveCMPTransactionInput) (*storage.CMPTransaction, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	if err := dmsValidate.Struct(input); err != nil {
		lFunc.Errorf("ApproveCMPTransaction: invalid input: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, dms, err := svc.dmsStorage.SelectExists(ctx, input.DMSID)
	if err != nil {
		lFunc.Errorf("could not check DMS %s exists: %s", input.DMSID, err)
		return nil, err
	}
	if !exists {
		return nil, errs.ErrDMSNotFound
	}

	tx, ok, err := svc.cmptxStorage.SelectIncludingExpired(ctx, input.TransactionID)
	if err != nil {
		lFunc.Errorf("ApproveCMPTransaction: lookup tx %s: %s", input.TransactionID, err)
		return nil, err
	}
	// Cross-DMS access is treated as not-found so an operator scoped to one DMS
	// cannot probe another DMS's transaction IDs.
	if !ok || tx.DMSID != input.DMSID {
		return nil, errs.ErrCMPTransactionNotFound
	}
	if tx.State != storage.CMPTransactionStatePending {
		lFunc.Warnf("ApproveCMPTransaction: tx %s is in state %s, not PENDING", tx.TransactionID, tx.State)
		return nil, errs.ErrCMPTransactionNotPending
	}
	if !tx.ExpiresAt.IsZero() && tx.ExpiresAt.Before(time.Now()) {
		lFunc.Warnf("ApproveCMPTransaction: tx %s expired at %s", tx.TransactionID, tx.ExpiresAt)
		return nil, errs.ErrCMPTransactionNotPending
	}
	if tx.CSR == nil {
		lFunc.Errorf("ApproveCMPTransaction: tx %s has no stored CSR", tx.TransactionID)
		return nil, errs.ErrCMPTransactionNotPending
	}

	csr := (*x509.CertificateRequest)(tx.CSR)
	// Mark the context as pre-authenticated: the original IR/KUR was already
	// authenticated at submission time, so LWCEnroll/LWCReenroll must not
	// re-run client-cert validation (there is no CMP signer in the admin's
	// approval context).
	issuanceCtx := context.WithValue(ctx, core.LamassuContextKeyPreAuthenticated, true)
	var cert *x509.Certificate
	if tx.IsReenrollment {
		cert, err = svc.service.LWCReenroll(issuanceCtx, csr, input.DMSID)
	} else {
		cert, err = svc.service.LWCEnroll(issuanceCtx, csr, input.DMSID)
	}
	if err != nil {
		lFunc.Errorf("ApproveCMPTransaction: issuance failed for tx %s: %s", tx.TransactionID, err)
		// Keep the existing (approval-window) expiry so the failed row stays
		// visible to the operator rather than being swept on the short certConf
		// schedule.
		updated, updErr := svc.cmptxStorage.UpdateState(ctx, tx.TransactionID, storage.CMPTransactionStateIssueFailed, nil, err.Error(), tx.ExpiresAt)
		if updErr != nil {
			lFunc.Warnf("ApproveCMPTransaction: failed to mark tx %s ISSUE_FAILED: %s", tx.TransactionID, updErr)
		} else if !updated {
			// Row vanished between approval and persistence — likely swept by
			// DeleteExpired. Audit signal only; we cannot recover further here.
			lFunc.Warnf("ApproveCMPTransaction: no live row to mark ISSUE_FAILED for tx %s (already expired/deleted)", tx.TransactionID)
		}
		svc.emitApprovalTransition(ctx, lFunc, tx, cmpwfx.CMPStateRejected, "", err.Error())
		return nil, err
	}

	// Re-base the TTL from the long approval window down to the certConf window:
	// post-approval the row behaves exactly like a direct issuance awaiting
	// certConf. With implicit confirmation there is no certConf message — the
	// cert is confirmed the moment the device fetches it via pollReq — so this
	// window simply bounds how long the (actively polling) device has to pick
	// the certificate up.
	confTimeout := time.Duration(dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.ConfirmationTimeout)
	if confTimeout <= 0 {
		confTimeout = cmpCertConfDefaultTTL
	}
	issuedExpiry := time.Now().Add(confTimeout)

	certSerial := helpers.SerialNumberToHexString(cert.SerialNumber)
	updated, updErr := svc.cmptxStorage.UpdateState(ctx, tx.TransactionID, storage.CMPTransactionStateIssued, (*models.X509Certificate)(cert), "", issuedExpiry)
	if updErr != nil {
		lFunc.Errorf("ApproveCMPTransaction: failed to mark tx %s ISSUED: %s", tx.TransactionID, updErr)
		return nil, updErr
	}
	if !updated {
		// The certificate has been issued at the CA but the transaction row
		// was already expired or removed. The cert is orphaned in Lamassu's
		// view; surface it as an error so the caller (admin tooling) can
		// reconcile rather than silently dropping the issuance.
		lFunc.Errorf("ApproveCMPTransaction: tx %s row missing/expired when persisting ISSUED state — cert %s is now orphaned", tx.TransactionID, certSerial)
		return nil, fmt.Errorf("CMP transaction %s no longer exists after issuance (cert %s orphaned; investigate cleanup vs approval timing)", tx.TransactionID, certSerial)
	}
	lFunc.Infof("ApproveCMPTransaction: tx %s approved, certificate %s issued", tx.TransactionID, certSerial)

	// Mirror the admin-gated issuance into WFX: AwaitingApproval → Responded
	// (admin) then Responded → AwaitingCertConf (server now awaits the EE's
	// certConf, retrieved alongside the cert via pollReq).
	svc.emitApprovalTransition(ctx, lFunc, tx, cmpwfx.CMPStateResponded, certSerial, "")
	svc.emitApprovalTransition(ctx, lFunc, tx, cmpwfx.CMPStateAwaitingCertConf, certSerial, "")

	// Reflect the issued outcome on the returned row in-memory; these are the
	// only fields UpdateState changed.
	tx.State = storage.CMPTransactionStateIssued
	tx.Certificate = (*models.X509Certificate)(cert)
	tx.CertSerialNumber = certSerial
	tx.ExpiresAt = issuedExpiry
	return &tx, nil
}

// RejectCMPTransaction denies a PENDING phased-workflow CMP transaction
// without issuing a certificate: the row moves to ISSUE_FAILED carrying the
// administrator's reason, which pollReq later surfaces as an error PKIMessage
// to the EE. Mirrors ApproveCMPTransaction's validation, scoping, and WFX
// emission semantics.
func (svc DMSManagerServiceBackend) RejectCMPTransaction(ctx context.Context, input services.RejectCMPTransactionInput) (*storage.CMPTransaction, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	if err := dmsValidate.Struct(input); err != nil {
		lFunc.Errorf("RejectCMPTransaction: invalid input: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, _, err := svc.dmsStorage.SelectExists(ctx, input.DMSID)
	if err != nil {
		lFunc.Errorf("could not check DMS %s exists: %s", input.DMSID, err)
		return nil, err
	}
	if !exists {
		return nil, errs.ErrDMSNotFound
	}

	tx, ok, err := svc.cmptxStorage.SelectIncludingExpired(ctx, input.TransactionID)
	if err != nil {
		lFunc.Errorf("RejectCMPTransaction: lookup tx %s: %s", input.TransactionID, err)
		return nil, err
	}
	// Cross-DMS access is treated as not-found (same as ApproveCMPTransaction).
	if !ok || tx.DMSID != input.DMSID {
		return nil, errs.ErrCMPTransactionNotFound
	}
	if tx.State != storage.CMPTransactionStatePending {
		lFunc.Warnf("RejectCMPTransaction: tx %s is in state %s, not PENDING", tx.TransactionID, tx.State)
		return nil, errs.ErrCMPTransactionNotPending
	}
	if !tx.ExpiresAt.IsZero() && tx.ExpiresAt.Before(time.Now()) {
		lFunc.Warnf("RejectCMPTransaction: tx %s expired at %s", tx.TransactionID, tx.ExpiresAt)
		return nil, errs.ErrCMPTransactionNotPending
	}

	reason := input.Reason
	if reason == "" {
		reason = "transaction rejected by administrator"
	}

	// Keep the existing PENDING TTL on the ISSUE_FAILED row so the operator
	// keeps seeing it until DeleteExpired sweeps it on the same schedule a
	// timed-out approval would have followed.
	updated, updErr := svc.cmptxStorage.UpdateState(ctx, tx.TransactionID, storage.CMPTransactionStateIssueFailed, nil, reason, tx.ExpiresAt)
	if updErr != nil {
		lFunc.Errorf("RejectCMPTransaction: failed to mark tx %s ISSUE_FAILED: %s", tx.TransactionID, updErr)
		return nil, updErr
	}
	if !updated {
		lFunc.Errorf("RejectCMPTransaction: tx %s row missing/expired when persisting ISSUE_FAILED state", tx.TransactionID)
		return nil, errs.ErrCMPTransactionNotPending
	}
	lFunc.Infof("RejectCMPTransaction: tx %s rejected (%s)", tx.TransactionID, reason)

	svc.emitApprovalTransition(ctx, lFunc, tx, cmpwfx.CMPStateRejected, "", reason)

	tx.State = storage.CMPTransactionStateIssueFailed
	tx.ErrorMessage = reason
	return &tx, nil
}

// emitApprovalTransition pushes one phased-workflow state transition into WFX,
// keyed to the transaction's existing job. No-op when WFX is disabled.
func (svc DMSManagerServiceBackend) emitApprovalTransition(ctx context.Context, lFunc *logrus.Entry, tx storage.CMPTransaction, state cmpwfx.CMPState, certSerial, reason string) {
	if svc.cmpWFXReporter == nil {
		return
	}
	if _, err := svc.cmpWFXReporter.Emit(ctx, cmpwfx.CMPTransition{
		TransactionID:     tx.TransactionID,
		DMSID:             tx.DMSID,
		RequestType:       tx.RequestType,
		SubjectCommonName: tx.SubjectCommonName,
		CertSerialNumber:  certSerial,
		State:             state,
		Reason:            reason,
		Workflow:          cmpwfx.CMPWorkflowNamePhased,
	}); err != nil {
		lFunc.WithField("cmpState", state).Warnf("ApproveCMPTransaction: WFX transition export failed: %v", err)
	}
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

func (svc DMSManagerServiceBackend) LWCProtectionCredentials(ctx context.Context, aps string) ([]*x509.Certificate, crypto.Signer, error) {
	exists, dms, err := svc.dmsStorage.SelectExists(ctx, aps)
	if err != nil {
		return nil, nil, fmt.Errorf("could not look up DMS '%s': %w", aps, err)
	}
	if !exists {
		return nil, nil, fmt.Errorf("DMS '%s' not found", aps)
	}

	protectionCertSN := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.ProtectionCertificateSerialNumber
	if protectionCertSN == "" {
		// No protection cert configured: the DMS opts out of response signing.
		// (nil chain, nil signer, nil error) signals "send unprotected response"
		// to the controller — distinct from a true error such as KMS unreachable.
		return nil, nil, nil
	}

	cert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: protectionCertSN})
	if err != nil {
		return nil, nil, fmt.Errorf("could not get protection certificate '%s': %w", protectionCertSN, err)
	}

	caSigner := NewCertificateSigner(ctx, cert, svc.kmsClient)
	leaf := (*x509.Certificate)(cert.Certificate)

	chain := append([]*x509.Certificate{leaf}, svc.walkCAChain(ctx, cert.IssuerCAMetadata.ID)...)
	return chain, caSigner, nil
}

// walkCAChain returns the issuer CA chain starting at startCAID and walking up
// to the root. Returns an empty slice when startCAID is empty.
// A maximum depth of 10 guards against pathological loops in misconfigured CA
// hierarchies; in practice CA hierarchies are at most a few levels deep.
func (svc DMSManagerServiceBackend) walkCAChain(ctx context.Context, startCAID string) []*x509.Certificate {
	const maxDepth = 10
	chain := make([]*x509.Certificate, 0, maxDepth)
	currentID := startCAID
	visited := make(map[string]struct{}, maxDepth)

	for i := 0; i < maxDepth && currentID != ""; i++ {
		if _, seen := visited[currentID]; seen {
			break
		}
		visited[currentID] = struct{}{}

		ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{CAID: currentID})
		if err != nil || ca == nil {
			break
		}
		chain = append(chain, (*x509.Certificate)(ca.Certificate.Certificate))

		// Stop when the CA is self-signed (root) or no parent is recorded.
		if ca.Certificate.IssuerCAMetadata.ID == "" || ca.Certificate.IssuerCAMetadata.ID == currentID {
			break
		}
		currentID = ca.Certificate.IssuerCAMetadata.ID
	}
	return chain
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
	if idSlot == nil {
		idSlot = &models.Slot[string]{
			Status:         models.SlotActive,
			ActiveVersion:  0,
			SecretType:     models.X509SlotProfileType,
			ExpirationDate: &crt.ValidTo,
			Secrets: map[int]string{
				0: crt.SerialNumber,
			},
			Events: map[time.Time]models.DeviceEvent{
				time.Now(): {
					EvenType: models.DeviceEventTypeProvisioned,
				},
			},
		}
	} else {
		idSlot.ActiveVersion = idSlot.ActiveVersion + 1
		idSlot.Status = models.SlotActive
		idSlot.ExpirationDate = &crt.ValidTo
		idSlot.Secrets[idSlot.ActiveVersion] = crt.SerialNumber

		idSlot.Events[time.Now()] = models.DeviceEvent{
			EvenType:          input.BindMode,
			EventDescriptions: fmt.Sprintf("New Active Version set to %d", idSlot.ActiveVersion),
		}
	}
	_, err = svc.deviceManagerCli.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
		ID:   crt.Subject.CommonName,
		Slot: *idSlot,
	})
	if err != nil {
		lFunc.Errorf("could not update device '%s' identity slot. Aborting enrollment process: %s", device.ID, err)
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
