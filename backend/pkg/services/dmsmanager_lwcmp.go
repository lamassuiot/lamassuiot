package services

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"golang.org/x/crypto/ocsp"
)

func (svc DMSManagerServiceBackend) LWCEnroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lFunc.Errorf("aborting enrollment. Could not get DMS '%s': %s", aps, err)
		return nil, errs.ErrDMSNotFound
	}

	enrollCA := dms.Settings.EnrollmentSettings.EnrollmentCA
	if cmpCA := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.EnrollmentCA; cmpCA != "" {
		enrollCA = cmpCA
	}
	lFunc = lFunc.WithField("dms", dms.ID)

	var existingDevice *models.Device
	existingDevice, err = svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: csr.Subject.CommonName})
	if err != nil && err != errs.ErrDeviceNotFound {
		lFunc.Errorf("could not get device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	enrollSettings := dms.Settings.EnrollmentSettings
	device, err := svc.ensureDeviceRegistered(ctx, lFunc, enrollSettings, dms.ID, csr.Subject.CommonName, existingDevice)
	if err != nil {
		return nil, err
	}

	issuanceProfile, err := svc.resolveIssuanceProfile(ctx, lFunc, dms, enrollCA)
	if err != nil {
		return nil, err
	}

	lFunc.Infof("requesting certificate signature")
	crt, err := svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
		CAID:            enrollCA,
		CertRequest:     (*models.X509CertificateRequest)(csr),
		IssuanceProfile: issuanceProfile,
	})
	if err != nil {
		lFunc.Errorf("could not issue certificate for device: %s", err)
		return nil, err
	}

	bindMode := models.DeviceEventTypeProvisioned
	if device.IdentitySlot != nil {
		bindMode = models.DeviceEventTypeReProvisioned
	}

	_, err = svc.service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                csr.Subject.CommonName,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                bindMode,
	})
	if err != nil {
		lFunc.Errorf("could not assign certificate to device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil
}

func (svc DMSManagerServiceBackend) LWCReenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lFunc.Errorf("aborting reenrollment. Could not get DMS '%s': %s", aps, err)
		return nil, errs.ErrDMSNotFound
	}

	enrollSettings := dms.Settings.EnrollmentSettings
	enrollCA := enrollSettings.EnrollmentCA
	if cmpCA := enrollSettings.EnrollmentOptionsLWCRFC9483.EnrollmentCA; cmpCA != "" {
		enrollCA = cmpCA
	}

	device, err := svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: csr.Subject.CommonName,
	})
	if err != nil {
		lFunc.Errorf("could not get device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	if device.IdentitySlot == nil {
		lFunc.Errorf("device '%s' has no identity slot", csr.Subject.CommonName)
		return nil, fmt.Errorf("device has no identity slot")
	}

	currentDeviceCertSN := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
	currentDeviceCert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: currentDeviceCertSN,
	})
	if err != nil {
		lFunc.Errorf("could not get device certificate '%s': %s", currentDeviceCertSN, err)
		return nil, fmt.Errorf("could not get device certificate")
	}

	if currentDeviceCert.Status == models.StatusRevoked {
		lFunc.Errorf("aborting reenrollment. certificate %s is revoked", currentDeviceCertSN)
		return nil, fmt.Errorf("revoked certificate")
	}

	issuanceProfile, err := svc.resolveIssuanceProfile(ctx, lFunc, dms, enrollCA)
	if err != nil {
		return nil, err
	}

	crt, err := svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
		CAID:            enrollCA,
		CertRequest:     (*models.X509CertificateRequest)(csr),
		IssuanceProfile: issuanceProfile,
	})
	if err != nil {
		lFunc.Errorf("could not issue certificate for device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

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

	reEnrollSettings := dms.Settings.ReEnrollmentSettings
	if currentDeviceCert.Status == models.StatusActive && reEnrollSettings.RevokeOnReEnrollment {
		_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
			SerialNumber:     currentDeviceCertSN,
			NewStatus:        models.StatusRevoked,
			RevocationReason: ocsp.Superseded,
		})
		if err != nil {
			lFunc.Errorf("could not revoke superseded certificate %s: %s", currentDeviceCert.SerialNumber, err)
			return nil, err
		}
	}

	_, err = svc.service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                models.DeviceEventTypeRenewed,
	})
	if err != nil {
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil
}

func (svc DMSManagerServiceBackend) LWCCACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return svc.CACerts(ctx, aps)
}

func (svc DMSManagerServiceBackend) LWCRevokeCertificate(ctx context.Context, input services.RevokeCertificateInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	_, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: input.APS,
	})
	if err != nil {
		lFunc.Errorf("aborting revocation. Could not get DMS '%s': %s", input.APS, err)
		return errs.ErrDMSNotFound
	}

	_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
		SerialNumber:     input.SerialNumber,
		NewStatus:        models.StatusRevoked,
		RevocationReason: input.Reason,
	})
	if err != nil {
		lFunc.Errorf("could not revoke certificate '%s': %s", input.SerialNumber, err)
		return err
	}

	return nil
}

func (svc DMSManagerServiceBackend) LWCGetEnrollmentOptions(ctx context.Context, aps string) (*services.LWCEnrollmentOptions, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("LWCGetEnrollmentOptions: could not get DMS '%s': %s", aps, err)
		return nil, err
	}
	opts := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483
	return &opts, nil
}

func (svc DMSManagerServiceBackend) LWCGetRootCACertUpdate(ctx context.Context, input services.GetRootCACertUpdateInput) (*services.RootCACertUpdateOutput, error) {
	// Root CA key rollover is not currently supported; signal no update available.
	return nil, nil
}

func (svc DMSManagerServiceBackend) LWCGetCertReqTemplate(ctx context.Context, input services.GetCertReqTemplateInput) (*services.CertReqTemplateOutput, error) {
	// No CA-mandated template restrictions; clients may use any subject/key.
	return nil, nil
}

func (svc DMSManagerServiceBackend) LWCGetCRL(ctx context.Context, input services.GetCMPCRLInput) (*x509.RevocationList, error) {
	// CRL distribution is handled by the VA/CRL service, not the DMS manager.
	return nil, nil
}
