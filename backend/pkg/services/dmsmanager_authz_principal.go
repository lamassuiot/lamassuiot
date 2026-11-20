package services

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/api/dto"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
)

func dmsPrincipalID(dmsID string) string {
	return "dms:" + dmsID
}

func authzPrincipalEnabled(settings models.DMSSettings) bool {
	return settings.AuthzPrincipalSettings != nil && settings.AuthzPrincipalSettings.Enabled
}

// syncAuthzPrincipal makes the principal of dms trust its enrollment CA and hold the configured policies.
// undo puts the principal back as it was before this call, so a failed save does not change which certificates are trusted.
func (svc DMSManagerServiceBackend) syncAuthzPrincipal(ctx context.Context, dms *models.DMS) (undo func(cause string), err error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	if svc.authz == nil {
		return nil, fmt.Errorf("%w: authz principal creation is disabled in the DMS Manager", errs.ErrValidateBadRequest)
	}
	caID := dms.Settings.EnrollmentSettings.EnrollmentCA
	if caID == "" {
		return nil, fmt.Errorf("%w: an authz principal needs an enrollment CA", errs.ErrValidateBadRequest)
	}
	ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
	if errors.Is(err, errs.ErrCANotFound) {
		return nil, fmt.Errorf("%w: enrollment CA %s not found", errs.ErrValidateBadRequest, caID)
	} else if err != nil {
		return nil, fmt.Errorf("could not get enrollment CA %s: %w", caID, err)
	}
	if ca.Certificate.Status != models.StatusActive {
		return nil, fmt.Errorf("%w: enrollment CA %s is %s, an authz principal can only trust an active CA", errs.ErrValidateBadRequest, caID, ca.Certificate.Status)
	}
	if ca.Certificate.Certificate == nil {
		return nil, fmt.Errorf("enrollment CA %s has no certificate", caID)
	}

	// authz grants unknown policy ids silently, so check them before creating anything.
	for _, policyID := range svc.authzPrincipals.PolicyIDs {
		if _, err := svc.authz.Policies.Get(ctx, policyID); err != nil {
			return nil, fmt.Errorf("could not check policy %s of authz_principals.policy_ids: %w", policyID, err)
		}
	}

	id := dmsPrincipalID(dms.ID)
	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	authConfig := dmsPrincipalAuthConfig(caCert, svc.authzPrincipals.SubjectAttributeMappings)
	name := fmt.Sprintf("RA %s", dms.Name)
	description := fmt.Sprintf("Managed by the DMS Manager for RA %s: trusts every certificate signed by %q. Edit the RA, not this principal.", dms.ID, caCert.Subject.CommonName)

	existing, err := svc.authz.Principals.Get(ctx, id)
	switch {
	case err == nil && existing.Type != "x509":
		return nil, fmt.Errorf("authz principal %s already exists with type %q", id, existing.Type)
	case err == nil:
		_, err = svc.authz.Principals.Update(ctx, id, &dto.UpdatePrincipalRequest{Name: &name, Description: &description, AuthConfig: &authConfig})
		undo = func(cause string) {
			restore := &dto.UpdatePrincipalRequest{Name: &existing.Name, Description: &existing.Description, AuthConfig: existing.AuthConfig}
			if _, restoreErr := svc.authz.Principals.Update(context.WithoutCancel(ctx), id, restore); restoreErr != nil {
				lFunc.Errorf("could not restore authz principal of DMS '%s' after %s: %s", dms.ID, cause, restoreErr)
			}
		}
	case isAuthzNotFound(err):
		_, err = svc.authz.Principals.Create(ctx, &dto.CreatePrincipalRequest{ID: id, Name: name, Description: &description, Type: "x509", AuthConfig: &authConfig})
		undo = func(cause string) { svc.rollbackAuthzPrincipal(ctx, lFunc, dms.ID, cause) }
	}
	if err != nil {
		return nil, fmt.Errorf("could not save authz principal %s: %w", id, err)
	}

	if err := svc.syncAuthzPolicies(ctx, id); err != nil {
		undo("the failed policy sync")
		return nil, err
	}
	return undo, nil
}

// syncAuthzPolicies grants the configured policies and revokes the other grants made by the DMS Manager.
func (svc DMSManagerServiceBackend) syncAuthzPolicies(ctx context.Context, id string) error {
	granted, err := svc.authzGrants(ctx, id)
	if err != nil {
		return fmt.Errorf("could not read the policies of authz principal %s: %w", id, err)
	}

	wanted := svc.authzPrincipals.PolicyIDs
	for _, policyID := range wanted {
		if slices.ContainsFunc(granted, func(g dto.PrincipalPolicyResponse) bool { return g.PolicyID == policyID }) {
			continue
		}
		if err := svc.authz.Principals.GrantPolicy(ctx, id, &dto.GrantPolicyRequest{PolicyID: policyID, GrantedBy: models.DMSManagerSource}); err != nil {
			return fmt.Errorf("could not grant policy %s to authz principal %s: %w", policyID, id, err)
		}
	}
	for _, g := range granted {
		if g.GrantedBy != models.DMSManagerSource || slices.Contains(wanted, g.PolicyID) {
			continue
		}
		if err := svc.authz.Principals.RevokePolicy(ctx, id, g.PolicyID); err != nil {
			return fmt.Errorf("could not revoke policy %s from authz principal %s: %w", g.PolicyID, id, err)
		}
	}
	return nil
}

// authzGrants returns every grant of the principal; authz lists them in pages.
func (svc DMSManagerServiceBackend) authzGrants(ctx context.Context, id string) ([]dto.PrincipalPolicyResponse, error) {
	var grants []dto.PrincipalPolicyResponse
	query := map[string]string{}
	for {
		page, err := svc.authz.Principals.GetPolicies(ctx, id, query)
		if err != nil {
			return nil, err
		}
		grants = append(grants, page.List...)
		if page.NextBookmark == "" || page.NextBookmark == query["bookmark"] {
			return grants, nil
		}
		query["bookmark"] = page.NextBookmark
	}
}

// deleteAuthzPrincipal removes the principal of a DMS, and a missing one is not an error.
// With the feature disabled the principal is left behind and logged.
func (svc DMSManagerServiceBackend) deleteAuthzPrincipal(ctx context.Context, lFunc *logrus.Entry, dmsID string) error {
	id := dmsPrincipalID(dmsID)
	if svc.authz == nil {
		lFunc.Warnf("authz principal %s left behind: authz principal creation is disabled in the DMS Manager", id)
		return nil
	}
	// Get first: an authz older than this DMS Manager answers 500 when deleting a missing principal.
	if _, err := svc.authz.Principals.Get(ctx, id); isAuthzNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("could not read authz principal %s: %w", id, err)
	}
	if err := svc.authz.Principals.Delete(ctx, id); err != nil && !isAuthzNotFound(err) {
		return fmt.Errorf("could not delete authz principal %s: %w", id, err)
	}
	return nil
}

// rollbackAuthzPrincipal deletes a principal created by this request after a later step failed.
func (svc DMSManagerServiceBackend) rollbackAuthzPrincipal(ctx context.Context, lFunc *logrus.Entry, dmsID, cause string) {
	if rollbackErr := svc.deleteAuthzPrincipal(context.WithoutCancel(ctx), lFunc, dmsID); rollbackErr != nil {
		lFunc.Errorf("could not rollback authz principal of DMS '%s' after %s: %s", dmsID, cause, rollbackErr)
	}
}

// dmsPrincipalAuthConfig matches any certificate signed by ca, pinned by its SHA-256 fingerprint.
func dmsPrincipalAuthConfig(ca *x509.Certificate, mappings map[string]string) authzmodels.AuthConfig {
	sum := sha256.Sum256(ca.Raw)
	cfg := authzmodels.AuthConfig{
		"match_mode": "any_from_ca",
		"ca_trust": map[string]any{
			"identity_type": "fingerprint",
			"value":         "SHA256:" + strings.ToUpper(hex.EncodeToString(sum[:])),
			"pem":           base64.StdEncoding.EncodeToString([]byte(chelpers.CertificateToPEM(ca))),
		},
	}
	if len(mappings) > 0 {
		m := make(map[string]any, len(mappings))
		for k, v := range mappings {
			m[k] = v
		}
		cfg["subject_attribute_mappings"] = m
	}
	return cfg
}

func isAuthzNotFound(err error) bool {
	var apiErr *authzsdk.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}
