package server

import (
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestMTLSStartupLog(t *testing.T) {
	tests := []struct {
		name string
		mode cconfig.MutualTLSMode
		want string
	}{
		{name: "strict", mode: cconfig.Strict, want: "with mTLS enabled using 'strict' validation mode"},
		{name: "any", mode: cconfig.Any, want: "with mTLS enabled using 'any' validation mode (at least one client certificate MUST be sent but wont be validated)"},
		{name: "request", mode: cconfig.Request, want: "with mTLS enabled using 'request' validation mode (client certificate will be request although not mandatory to be sent. Behaves like optional mTLS)"},
		{name: "empty defaults to strict", want: "with mTLS enabled using 'strict' validation mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authentication := cconfig.HttpServerAuthentication{}
			authentication.MutualTLS.Enabled = true
			authentication.MutualTLS.ValidationMode = tt.mode
			require.Equal(t, tt.want, mtlsStartupLog(authentication))
		})
	}

	require.Empty(t, mtlsStartupLog(cconfig.HttpServerAuthentication{}))
}
