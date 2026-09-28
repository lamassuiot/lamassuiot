package routes

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTenantOpenAPIContractsMatchRegisteredMethods(t *testing.T) {
	contractFiles := map[string]string{
		"ca":             "ca-openapi.yaml",
		"kms":            "kms-openapi.yaml",
		"device-manager": "device-manager-openapi.yaml",
		"dms-manager":    "dms-manager-openapi.yaml",
		"va":             "va-openapi.yaml",
		"alerts":         "alerts-openapi.yaml",
	}
	legacyServers := map[string]string{
		"ca":             "/api/ca/v1",
		"kms":            "/api/kms/v1",
		"device-manager": "/api/devmanager/v1",
		"dms-manager":    "/api/dmsmanager/v1",
		"va":             "/api/va/v1",
		"alerts":         "/api/alerts/v1",
	}

	for _, group := range tenantAdministrativeEndpointGroups {
		group := group
		t.Run(group.service, func(t *testing.T) {
			contractPath := filepath.Join("..", "..", "..", "docs", contractFiles[group.service])
			contents, err := os.ReadFile(contractPath)
			if err != nil {
				t.Fatalf("read OpenAPI contract %s: %v", contractPath, err)
			}
			var document map[string]interface{}
			if err := yaml.Unmarshal(contents, &document); err != nil {
				t.Fatalf("parse OpenAPI contract %s: %v", contractPath, err)
			}

			info := openAPIMap(t, document["info"], "info")
			if version, _ := info["version"].(string); version != "2.0.0" {
				t.Errorf("expected OpenAPI contract version 2.0.0, got %q", version)
			}
			servers, ok := document["servers"].([]interface{})
			if !ok || len(servers) < 2 {
				t.Fatalf("expected v2 and v1 compatibility servers")
			}
			wantV2Server := fmt.Sprintf("/api/%s/api/v2/tenants/{tenantId}", openAPIServiceName(group.service))
			v2Server := openAPIMap(t, servers[0], "servers[0]")
			if got, _ := v2Server["url"].(string); got != wantV2Server {
				t.Errorf("expected canonical v2 server %q first, got %q", wantV2Server, got)
			}
			variables := openAPIMap(t, v2Server["variables"], "servers[0].variables")
			tenantIDVariable := openAPIMap(t, variables["tenantId"], "servers[0].variables.tenantId")
			if defaultTenant, _ := tenantIDVariable["default"].(string); defaultTenant == "" {
				t.Errorf("v2 server tenantId variable must have a non-empty example default")
			}
			if got, _ := openAPIMap(t, servers[1], "servers[1]")["url"].(string); got != legacyServers[group.service] {
				t.Errorf("expected v1 compatibility server %q, got %q", legacyServers[group.service], got)
			}

			paths := openAPIMap(t, document["paths"], "paths")
			wantOperations := make(map[string]struct{}, len(group.endpoints))
			for _, endpoint := range group.endpoints {
				wantOperations[strings.ToLower(endpoint.method)+" "+openAPIPath(endpoint.path)] = struct{}{}
			}
			gotOperations := make(map[string]struct{})
			for path, rawItem := range paths {
				pathItem := openAPIMap(t, rawItem, "paths["+path+"]")
				if isProtocolPath(path) {
					wantProtocolServer := "/api/va"
					if group.service == "dms-manager" {
						wantProtocolServer = "/api/dmsmanager"
					}
					protocolServers, ok := pathItem["servers"].([]interface{})
					if !ok || len(protocolServers) != 1 {
						t.Errorf("protocol path %s must override tenant-scoped servers", path)
					} else if got, _ := openAPIMap(t, protocolServers[0], path+" servers")["url"].(string); got != wantProtocolServer {
						t.Errorf("protocol path %s must use server %q, got %q", path, wantProtocolServer, got)
					}
					continue
				}
				for method := range openAPIHTTPMethods {
					if _, exists := pathItem[method]; exists {
						gotOperations[method+" "+path] = struct{}{}
					}
				}
			}
			for operation := range wantOperations {
				if _, exists := gotOperations[operation]; !exists {
					t.Errorf("OpenAPI contract is missing registered operation %s", operation)
				}
			}
			for operation := range gotOperations {
				if _, exists := wantOperations[operation]; !exists {
					t.Errorf("OpenAPI contract contains unregistered administrative operation %s", operation)
				}
			}
		})
	}
}

var openAPIHTTPMethods = map[string]struct{}{
	"get": {}, "put": {}, "post": {}, "delete": {}, "options": {}, "head": {}, "patch": {}, "trace": {},
}

func openAPIMap(t *testing.T, value interface{}, field string) map[string]interface{} {
	t.Helper()
	result, ok := value.(map[string]interface{})
	if !ok {
		t.Fatalf("expected %s to be an object, got %T", field, value)
	}
	return result
}

func openAPIServiceName(service string) string {
	if service == "device-manager" {
		return "devmanager"
	}
	if service == "dms-manager" {
		return "dmsmanager"
	}
	return service
}

func openAPIPath(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		if strings.HasPrefix(segment, ":") {
			segments[index] = "{" + strings.TrimPrefix(segment, ":") + "}"
		}
	}
	return strings.Join(segments, "/")
}

func isProtocolPath(path string) bool {
	return strings.HasPrefix(path, "/.well-known/est/") || strings.HasPrefix(path, "/ocsp") || strings.HasPrefix(path, "/crl/")
}
