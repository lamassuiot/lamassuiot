package dmsmanager

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20261021120000WebhookHTTPClientConfig() {
	goose.AddMigrationContext(upWebhookHTTPClientConfig, downWebhookHTTPClientConfig)
}

// upWebhookHTTPClientConfig rewrites the external webhook client config of the
// enrollment and reenrollment settings into the config.HTTPClient JSON layout.
func upWebhookHTTPClientConfig(ctx context.Context, tx *sql.Tx) error {
	return rewriteWebhookHTTPClientConfigs(ctx, tx, migrateWebhookHTTPClientConfig)
}

// downWebhookHTTPClientConfig restores the legacy layout.
func downWebhookHTTPClientConfig(ctx context.Context, tx *sql.Tx) error {
	return rewriteWebhookHTTPClientConfigs(ctx, tx, revertWebhookHTTPClientConfig)
}

// rewriteWebhookHTTPClientConfigs applies rewrite to every external webhook
// client config and stores the DMS settings that changed.
func rewriteWebhookHTTPClientConfigs(ctx context.Context, tx *sql.Tx, rewrite func(map[string]any) bool) error {
	rows, err := tx.QueryContext(ctx, "SELECT id, settings FROM dms")
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	for _, r := range result {
		settingsRaw, ok := r["settings"].(string)
		if !ok {
			return fmt.Errorf("invalid settings type for dms %v", r["id"])
		}

		var settings map[string]any
		if err := json.Unmarshal([]byte(settingsRaw), &settings); err != nil {
			return fmt.Errorf("failed to unmarshal settings for dms %v: %w", r["id"], err)
		}

		changed := false
		for _, section := range []string{"enrollment_settings", "reenrollment_settings"} {
			webhookConfig := nestedMap(settings, section, "est_rfc7030_settings", "external_webhook_settings", "config")
			if webhookConfig != nil && rewrite(webhookConfig) {
				changed = true
			}
		}
		if !changed {
			continue
		}

		newSettings, err := json.Marshal(settings)
		if err != nil {
			return fmt.Errorf("failed to marshal settings for dms %v: %w", r["id"], err)
		}

		_, err = tx.ExecContext(ctx, "UPDATE dms SET settings = $1 WHERE id = $2", string(newSettings), r["id"])
		if err != nil {
			return err
		}
	}

	return nil
}

func nestedMap(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		next, ok := m[k].(map[string]any)
		if !ok {
			return nil
		}
		m = next
	}
	return m
}

// migrateWebhookHTTPClientConfig converts the legacy layout in place:
//
//	validate_server_cert     -> insecure_skip_verify (negated)
//	oidc{client_id,...}      -> jwt_options{oidc_client_id,...}
//	apikey{key,header}       -> apikey_options{key,header}
//	mtls{cert,key}           -> mtls_options{cert_content,key_content} when both
//	                            values are PEM, {cert_file,key_file} otherwise
//	                            (rejected when the webhook is saved or invoked)
func migrateWebhookHTTPClientConfig(cfg map[string]any) bool {
	changed := false
	if v, ok := cfg["validate_server_cert"]; ok {
		validate, _ := v.(bool)
		cfg["insecure_skip_verify"] = !validate
		delete(cfg, "validate_server_cert")
		changed = true
	}

	if oidc, ok := cfg["oidc"].(map[string]any); ok {
		cfg["jwt_options"] = map[string]any{
			"oidc_client_id":     oidc["client_id"],
			"oidc_client_secret": oidc["client_secret"],
			"oidc_well_known":    oidc["well_known"],
		}
		delete(cfg, "oidc")
		changed = true
	}

	if apikey, ok := cfg["apikey"].(map[string]any); ok {
		cfg["apikey_options"] = map[string]any{
			"key":    apikey["key"],
			"header": apikey["header"],
		}
		delete(cfg, "apikey")
		changed = true
	}

	if mtls, ok := cfg["mtls"].(map[string]any); ok {
		cert, _ := mtls["cert"].(string)
		key, _ := mtls["key"].(string)
		switch {
		case strings.Contains(cert, "-----BEGIN") && strings.Contains(key, "-----BEGIN"):
			cfg["mtls_options"] = map[string]any{"cert_content": cert, "key_content": key}
		case cert != "" || key != "":
			cfg["mtls_options"] = map[string]any{"cert_file": cert, "key_file": key}
		}
		delete(cfg, "mtls")
		changed = true
	}

	return changed
}

// legacyPEM returns the plain PEM of a cert_content/key_content value. The
// legacy model only reads plain PEM, so base64-encoded PEM is decoded; any
// other value is returned untouched.
func legacyPEM(v any) any {
	s, ok := v.(string)
	if !ok || strings.Contains(s, "-----BEGIN") {
		return v
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || !strings.Contains(string(decoded), "-----BEGIN") {
		return v
	}
	return string(decoded)
}

// revertWebhookHTTPClientConfig is the inverse of migrateWebhookHTTPClientConfig.
// Options without a legacy equivalent (ca_cert_file, hostname, ...) are left
// in place: the legacy model ignores them.
func revertWebhookHTTPClientConfig(cfg map[string]any) bool {
	changed := false
	if v, ok := cfg["insecure_skip_verify"]; ok {
		insecure, _ := v.(bool)
		cfg["validate_server_cert"] = !insecure
		delete(cfg, "insecure_skip_verify")
		changed = true
	}

	if jwt, ok := cfg["jwt_options"].(map[string]any); ok {
		cfg["oidc"] = map[string]any{
			"client_id":     jwt["oidc_client_id"],
			"client_secret": jwt["oidc_client_secret"],
			"well_known":    jwt["oidc_well_known"],
		}
		delete(cfg, "jwt_options")
		changed = true
	}

	if apikey, ok := cfg["apikey_options"].(map[string]any); ok {
		cfg["apikey"] = map[string]any{
			"key":    apikey["key"],
			"header": apikey["header"],
		}
		delete(cfg, "apikey_options")
		changed = true
	}

	if mtls, ok := cfg["mtls_options"].(map[string]any); ok {
		cert, key := legacyPEM(mtls["cert_content"]), legacyPEM(mtls["key_content"])
		if cert == nil && key == nil {
			cert, key = mtls["cert_file"], mtls["key_file"]
		}
		cfg["mtls"] = map[string]any{"cert": cert, "key": key}
		delete(cfg, "mtls_options")
		changed = true
	}

	return changed
}
