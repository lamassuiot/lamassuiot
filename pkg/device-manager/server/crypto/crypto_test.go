package crypto

import "testing"

const keycloakPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHjb/vc9eAzk7/gzmoP1oqoLRPm9vhWBrfVnoxH4AE4u7g5lkBAg60Pct9MWlT8ag/eoV4TR23Hb6J7FXhuGXRyvmneLdRzI07iUSSrIUuZgB9Mg3mck9cIXoHDILx4MwxnBVRFcU5O5F0ieh8qRWWWbxLkRV8Ts7XjDUi1rfdZ0TLRBAt5XksQl64kK6MhZN7I+lS+CgoAZesLXYe5rv7GJ0Pb1sEnAIFzLFWcNKoCnjbqcpYhM8T92o2tz60MiI7xy1yQYmrz99uMeU0+khkzEIzssNOQy+oCMZ1PMK5MA5aTXbZrtOXoAdwAX5acPmp5bttiIL1eMc2K5ebSruQIDAQAB"
const csrData = "-----BEGIN CERTIFICATE REQUEST-----\nMIICoDCCAYgCAQAwWzELMAkGA1UEBhMCRVMxETAPBgNVBAgMCEdpcHV6a29hMREw\nDwYDVQQHDAhBcnJhc2F0ZTEQMA4GA1UECgwHRVhBTVBMRTEUMBIGA1UEAwwLRVhB\nTVBMRS5DT00wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXcJ/Vi2nr\nEKINfjpKWILMl07PuchVSfFsGN497nXTRdfyCfzUUVBgJ0gfYr/RsYzyR/iANOQs\n4gjfvXDESN7m7z3arL5DFA3PlMuGrtJChQbA4JlhcuOR0BaHsleUxkmUx1asrm9c\nM8wS6SQVwGjhFlA1CuWIY+c3WZOw0evQO3VDjGz3/RpFL0mDfpIink0rx4F/A0XI\nVeq2yxcIGRYStST3jEFyLjU375i7hOsbCcXY4sH9crh2XognywYFMkawbvyPHDJD\nYnS4GjSH04ItNz22UFI5E0a3rUNMXIekeyDbU1Qb7jfc2u1lLxhpsJ4rLb42VTop\nNVsI7ti5+Zn7AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAQVY7FdWQCiZE727B\nbHqFggWzB+OxpwladrYY1kIztDYYZNM84rP77oLg2Mw/IWCTowCNV3uIeyJ/fr4d\nPNYiJE1jnPug1TXn0qWPNxIHXbGhtbmOIcYl189cSbAyfDhWh9AU5lmX3y+O6gFs\nrc+QJeKVAnv+7lvh+LwhAXN2F5tALn++HPP2+YqH+/SnSx0iIA0yJCcUPBLJczgB\n0yk0iJKZDZp7Y3RqkljKEpHdKH0SmLMmIJg+nrm8DNzjlVQ2xpSUaeGMvSg5cEcP\nYGPaj9PQmt5BkXmkWq5PAB+C5j5fsgvljrOIW2Mdip2zDj/tXCYNy0gfcV1SAcMB\n/D4Vvg==\n-----END CERTIFICATE REQUEST-----"

func TestParseKeycloakPublicKey(t *testing.T) {
	key, err := ParseKeycloakPublicKey([]byte(PublicKeyHeader + "\n" + keycloakPublicKey + "\n" + PublicKeyFooter))
	if err != nil {
		t.Errorf("Crypto returned an error: %s", err)
	}
	if key == nil {
		t.Error("Crypto does not return a key")
	}
}

func TestParseNewCSR(t *testing.T) {
	csr, err := ParseNewCSR([]byte(csrData))
	if err != nil {
		t.Errorf("Crypto returned an error: %s", err)
	}
	if csr == nil {
		t.Error("Crypto does not return a CSR")
	}
}

func TestCreateCAPool(t *testing.T) {
	caPool, err := CreateCAPool("testdata/test.crt")
	if err != nil {
		t.Errorf("Crypto returned an error: %s", err)
	}
	if caPool == nil {
		t.Error("Crypto does not return a CA pool")
	}
}
