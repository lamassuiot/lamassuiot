package sdk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type certificateKeyTransport func(*http.Request) (*http.Response, error)

func (transport certificateKeyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func certificateKeyResponse(t *testing.T, status int, payload any) *http.Response {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}
}

func certificateKeyFixture(t *testing.T) (*models.X509Certificate, models.Key, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	id := hex.EncodeToString(digest[:])
	key := models.Key{KeyID: id, EngineID: "filesystem-test-1", HasPrivateKey: true,
		PKCS11URI: fmt.Sprintf("pkcs11:token-id=filesystem-test-1;id=%s;type=private", id),
		PublicKey: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}
	return (*models.X509Certificate)(&x509.Certificate{PublicKey: &private.PublicKey, SubjectKeyId: []byte{1}}), key, id
}

func TestGetCertificateKeyUsesExistingHTTPEndpoints(t *testing.T) {
	for _, strategy := range []string{"SKI", "digest", "wrong SKI candidate", "public key with pagination"} {
		t.Run(strategy, func(t *testing.T) {
			cert, key, digestID := certificateKeyFixture(t)
			if strategy == "SKI" {
				ski, err := hex.DecodeString(digestID)
				if err != nil {
					t.Fatal(err)
				}
				(*x509.Certificate)(cert).SubjectKeyId = ski
			}
			if strategy == "public key with pagination" {
				key.KeyID = "provider-key-id"
				key.PKCS11URI = "pkcs11:token-id=filesystem-test-1;id=provider-key-id;type=private"
			}
			var paths []string
			listPages := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			kmsClient := NewHttpKMSClient(&http.Client{Transport: certificateKeyTransport(func(request *http.Request) (*http.Response, error) {
				paths = append(paths, request.URL.Path)
				if request.URL.Host != "kms.example" {
					t.Fatalf("key lookup used the wrong service: %s", request.URL)
				}
				if request.Method != http.MethodGet {
					t.Fatalf("unexpected method: %s", request.Method)
				}
				if request.Context() != ctx {
					t.Fatal("request lost caller context")
				}
				if request.URL.Path == "/v1/keys" {
					listPages++
					if listPages == 1 {
						expected := []string{"public_key[eq]" + key.PublicKey, "engine_id[eq]" + key.EngineID}
						if !reflect.DeepEqual(expected, request.URL.Query()["filter"]) {
							t.Fatalf("unexpected filters: %v", request.URL.Query())
						}
						publicOnly := key
						publicOnly.HasPrivateKey = false
						return certificateKeyResponse(t, 200, resources.GetKeysResponse{IterableList: resources.IterableList[models.Key]{List: []models.Key{publicOnly}, NextBookmark: "next-page"}}), nil
					}
					if listPages != 2 || request.URL.Query().Get("bookmark") != "next-page" {
						t.Fatalf("unexpected page: %s", request.URL.String())
					}
					return certificateKeyResponse(t, 200, resources.GetKeysResponse{IterableList: resources.IterableList[models.Key]{List: []models.Key{key}}}), nil
				}
				if request.URL.Path == "/v1/keys/"+key.PKCS11URI {
					return certificateKeyResponse(t, 200, key), nil
				}
				if strategy == "wrong SKI candidate" && len(paths) == 1 {
					_, wrong, _ := certificateKeyFixture(t)
					return certificateKeyResponse(t, 200, wrong), nil
				}
				if request.URL.Path != "/v1/keys/pkcs11:token-id=filesystem-test-1;id=01;type=private" && request.URL.Path != "/v1/keys/pkcs11:token-id=filesystem-test-1;id="+digestID+";type=private" {
					t.Fatalf("unexpected endpoint: %s", request.URL.Path)
				}
				return certificateKeyResponse(t, 404, map[string]string{"err": errs.ErrKeyNotFound.Error()}), nil
			})}, "https://kms.example")
			resolved, err := NewHttpCAClient(&http.Client{}, "https://ca.example", kmsClient).GetCertificateKey(ctx, services.GetCertificateKeyInput{Certificate: cert, EngineID: key.EngineID})
			if err != nil {
				t.Fatal(err)
			}
			if resolved.KeyID != key.KeyID || resolved.EngineID != key.EngineID {
				t.Fatalf("wrong resolved key: %+v", resolved)
			}
			expectedCalls := 2
			if strategy == "SKI" {
				expectedCalls = 1
			}
			if strategy == "public key with pagination" {
				expectedCalls = 4
			}
			if len(paths) != expectedCalls {
				t.Fatalf("expected %d requests, got %v", expectedCalls, paths)
			}
		})
	}
}

func TestGetCertificateKeyRequiresKMSClient(t *testing.T) {
	cert, _, _ := certificateKeyFixture(t)
	client := NewHttpCAClient(&http.Client{}, "https://ca.example")
	_, err := client.GetCertificateKey(context.Background(), services.GetCertificateKeyInput{Certificate: cert})
	if err == nil || !strings.Contains(err.Error(), "KMS client is required") {
		t.Fatalf("expected a missing KMS client error, got %v", err)
	}
}

func TestGetCertificateKeyHandlesHTTPAmbiguity(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprintf("ambiguous=%t", ambiguous), func(t *testing.T) {
			cert, key, _ := certificateKeyFixture(t)
			lookupCalls := 0
			kmsClient := NewHttpKMSClient(&http.Client{Transport: certificateKeyTransport(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/v1/keys" {
					keys := []models.Key{key}
					if ambiguous {
						other := key
						other.EngineID = "another-engine"
						keys = append(keys, other)
					}
					return certificateKeyResponse(t, 200, resources.GetKeysResponse{IterableList: resources.IterableList[models.Key]{List: keys}}), nil
				}
				lookupCalls++
				return certificateKeyResponse(t, 400, map[string]string{"err": errs.ErrKeyEngineRequired.Error()}), nil
			})}, "https://kms.example")
			resolved, err := NewHttpCAClient(&http.Client{}, "https://ca.example", kmsClient).GetCertificateKey(context.Background(), services.GetCertificateKeyInput{Certificate: cert})
			if ambiguous {
				if !errors.Is(err, errs.ErrKeyEngineRequired) || resolved != nil {
					t.Fatalf("expected ambiguous engine, got %v, %v", resolved, err)
				}
			} else if err != nil || resolved.EngineID != key.EngineID {
				t.Fatalf("expected private key resolution, got %v, %v", resolved, err)
			}
			if lookupCalls != 2 {
				t.Fatalf("expected SKI and digest lookups, got %d", lookupCalls)
			}
		})
	}
}

func TestGetCertificateKeyDoesNotMaskHTTPFailures(t *testing.T) {
	for _, status := range []int{400, 401, 500} {
		t.Run(fmt.Sprintf("status=%d", status), func(t *testing.T) {
			cert, key, _ := certificateKeyFixture(t)
			calls := 0
			kmsClient := NewHttpKMSClient(&http.Client{Transport: certificateKeyTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				return certificateKeyResponse(t, status, map[string]string{"err": "KMS unavailable"}), nil
			})}, "https://kms.example")
			_, err := NewHttpCAClient(&http.Client{}, "https://ca.example", kmsClient).GetCertificateKey(context.Background(), services.GetCertificateKeyInput{Certificate: cert, EngineID: key.EngineID})
			if err == nil || !strings.Contains(err.Error(), "KMS unavailable") {
				t.Fatalf("expected HTTP failure, got %v", err)
			}
			if calls != 1 {
				t.Fatalf("HTTP failure triggered fallback: %d requests", calls)
			}
		})
	}
}
