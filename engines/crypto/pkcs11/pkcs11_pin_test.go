package pkcs11

import (
    "testing"

    "github.com/lamassuiot/lamassuiot/v4/engines/crypto/pkcs11/config"
    coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

func TestResolvePKCS11PIN(t *testing.T) {
    tests := []struct {
        name        string
        pin         string
        pinEnv      string
        envValue    string
        setEnv      bool
        wantPin     string
        wantError   bool
    }{
        {
            name:    "literal PIN",
            pin:     "1234",
            wantPin: "1234",
        },
        {
            name:      "PIN from environment",
            pinEnv:    "TEST_PKCS11_PIN",
            envValue:  "5678",
            setEnv:    true,
            wantPin:   "5678",
        },
        {
            name:      "missing environment variable",
            pinEnv:    "TEST_PKCS11_PIN_MISSING",
            wantError: true,
        },
        {
            name:      "empty environment variable",
            pinEnv:    "TEST_PKCS11_PIN_EMPTY",
            envValue:  "",
            setEnv:    true,
            wantError: true,
        },
        {
            name:      "both PIN sources configured",
            pin:       "1234",
            pinEnv:    "TEST_PKCS11_PIN",
            wantError: true,
        },
        {
            name:      "no PIN configured",
            wantError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if tt.setEnv {
                t.Setenv(tt.pinEnv, tt.envValue)
            }

            conf := coreconfig.CryptoEngineConfigAdapter[config.PKCS11Config]{
                ID: "test-engine",
                Config: config.PKCS11Config{
                    TokenPin: coreconfig.Password(tt.pin),
                    PinEnv:   tt.pinEnv,
                },
            }

            got, err := resolvePKCS11PIN(conf)

            if (err != nil) != tt.wantError {
                t.Fatalf("resolvePKCS11PIN() error = %v, wantError %v", err, tt.wantError)
            }

            if err == nil && got != tt.wantPin {
                t.Errorf("resolvePKCS11PIN() = %q, want %q", got, tt.wantPin)
            }
        })
    }
}