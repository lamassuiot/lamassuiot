package services

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	webhookclient "github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers/webhook-client"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

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
