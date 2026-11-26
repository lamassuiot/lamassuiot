package routes

import (
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func TestInjectVersionIntoOpenAPI(t *testing.T) {
	validSpec := func(version string) []byte {
		b, _ := yaml.Marshal(map[string]any{
			"openapi": "3.0.0",
			"info": map[string]any{
				"title":   "Test API",
				"version": version,
			},
		})
		return b
	}

	cases := []struct {
		name        string
		input       []byte
		version     string
		wantVersion string // empty means expect original bytes back
		wantSame    bool   // true when we expect the exact input returned
	}{
		{
			name:     "empty content",
			input:    []byte{},
			version:  "1.2.3",
			wantSame: true,
		},
		{
			name:     "empty version",
			input:    validSpec("0.0.0"),
			version:  "",
			wantSame: true,
		},
		{
			name:        "happy path — version replaced",
			input:       validSpec("0.0.0"),
			version:     "1.2.3",
			wantVersion: "1.2.3",
		},
		{
			name:        "version already correct — idempotent",
			input:       validSpec("1.2.3"),
			version:     "1.2.3",
			wantVersion: "1.2.3",
		},
		{
			name:     "invalid YAML — original returned",
			input:    []byte("{{not: valid: yaml::"),
			version:  "1.2.3",
			wantSame: true,
		},
		{
			name: "missing info section — original returned",
			input: func() []byte {
				b, _ := yaml.Marshal(map[string]any{"openapi": "3.0.0"})
				return b
			}(),
			version:  "1.2.3",
			wantSame: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InjectVersionIntoOpenAPI(tc.input, tc.version)

			if tc.wantSame {
				if string(got) != string(tc.input) {
					t.Fatalf("expected original bytes back\ngot:  %q\nwant: %q", got, tc.input)
				}
				return
			}

			var parsed map[string]any
			if err := yaml.Unmarshal(got, &parsed); err != nil {
				t.Fatalf("output is not valid YAML: %v", err)
			}
			info, ok := parsed["info"].(map[string]any)
			if !ok {
				t.Fatal("output missing info section")
			}
			if got := info["version"]; got != tc.wantVersion {
				t.Fatalf("version = %q, want %q", got, tc.wantVersion)
			}
		})
	}
}

func TestRunHttpRouterRejectsNegativeWriteTimeout(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	cfg := cconfig.HttpServer{ListenAddress: "127.0.0.1", Port: 0, Protocol: cconfig.HTTP, WriteTimeout: -time.Second}

	port, err := RunHttpRouter(logger, gin.New(), cfg, models.APIServiceInfo{}, nil)
	if port != -1 {
		t.Fatalf("expected port -1. Got %d", port)
	}
	if err == nil || !strings.Contains(err.Error(), "server.write_timeout") {
		t.Fatalf("expected error containing %q. Got %v", "server.write_timeout", err)
	}
}
