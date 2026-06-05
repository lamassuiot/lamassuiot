package api

import (
	"context"
	"fmt"
	"strings"

	authzconfig "github.com/lamassuiot/authz/pkg/config"
	authzmodels "github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/sirupsen/logrus"
)

// runBootstrap seeds principals and policy grants declared in conf.Bootstrap.
// It is called during AssembleAuthzService, after preloadPolicies, so any
// policies loaded from PreloadDir are already present when grants are applied.
// Every operation is idempotent: safe to run on every restart.
func runBootstrap(ctx context.Context, pm *service.PrincipalManager, entries []authzconfig.BootstrapEntry, log *logrus.Entry) error {
	for _, entry := range entries {
		if err := bootstrapPrincipal(ctx, pm, entry, log); err != nil {
			return err
		}
	}
	return nil
}

func bootstrapPrincipal(ctx context.Context, pm *service.PrincipalManager, entry authzconfig.BootstrapEntry, log *logrus.Entry) error {
	_, err := pm.GetPrincipal(ctx, entry.PrincipalID)
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("bootstrap: checking principal %q: %w", entry.PrincipalID, err)
		}
		name := entry.PrincipalName
		if name == "" {
			name = entry.PrincipalID
		}
		p := &authzmodels.Principal{
			ID:     entry.PrincipalID,
			Name:   name,
			Type:   entry.PrincipalType,
			Active: true,
		}
		if len(entry.AuthConfig) > 0 {
			p.AuthConfig = authzmodels.AuthConfig(entry.AuthConfig)
		}
		if err := pm.CreatePrincipal(ctx, p); err != nil {
			return fmt.Errorf("bootstrap: create principal %q: %w", entry.PrincipalID, err)
		}
		log.Infof("bootstrap: created principal %q", entry.PrincipalID)
	} else {
		log.Debugf("bootstrap: principal %q already exists", entry.PrincipalID)
	}

	for _, policyID := range entry.PolicyIDs {
		has, err := pm.HasPolicy(ctx, entry.PrincipalID, policyID)
		if err != nil {
			return fmt.Errorf("bootstrap: checking policy %q for principal %q: %w", policyID, entry.PrincipalID, err)
		}
		if has {
			log.Debugf("bootstrap: principal %q already has policy %q", entry.PrincipalID, policyID)
			continue
		}
		if err := pm.GrantPolicy(ctx, entry.PrincipalID, policyID, "bootstrap"); err != nil {
			return fmt.Errorf("bootstrap: grant policy %q to principal %q: %w", policyID, entry.PrincipalID, err)
		}
		log.Infof("bootstrap: granted policy %q to principal %q", policyID, entry.PrincipalID)
	}

	return nil
}
