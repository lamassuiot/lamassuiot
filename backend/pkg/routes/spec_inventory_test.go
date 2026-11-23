package routes

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEveryOpenAPISpecHasAnAssignedSuite(t *testing.T) {
	// Adding an API requires an explicit coverage suite rather than silently skipping it.
	suites := map[string]string{
		"docs/specs/ca-openapi.yaml":                      "TestCAOpenAPIContractCoversEveryEndpoint",
		"docs/specs/kms-openapi.yaml":                     "TestKMSOpenAPIContractCoversEveryEndpoint",
		"docs/specs/va-openapi.yaml":                      "TestVAOpenAPIContractCoversEveryEndpoint",
		"docs/specs/device-manager-openapi.yaml":          "TestDeviceManagerOpenAPIContractCoversEveryEndpoint",
		"docs/specs/alerts-openapi.yaml":                  "TestRemainingBackendOpenAPIContracts",
		"docs/specs/dms-manager-openapi.yaml":             "TestRemainingBackendOpenAPIContracts",
		"docs/specs/enroll-reenroll-webhook-openapi.yaml": "TestEnrollmentWebhookEveryOpenAPIOperation (services)",
		"docs/specs/authz-openapi.yaml":                   "TestAuthzOpenAPIAndEveryRegisteredGuard (authz API)",
	}
	root := "../../.."
	discovered := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.Contains(entry.Name(), "openapi") || !strings.HasSuffix(entry.Name(), ".yaml") {
			return nil
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, resolved)
		if err != nil {
			return err
		}
		suite, ok := suites[filepath.ToSlash(relative)]
		require.True(t, ok, "OpenAPI %s has no coverage suite", relative)
		require.NotEmpty(t, suite)
		discovered[filepath.ToSlash(relative)] = true
		return nil
	})
	require.NoError(t, err)
	require.Len(t, discovered, len(suites), "remove stale suite entries when deleting a spec")
}
