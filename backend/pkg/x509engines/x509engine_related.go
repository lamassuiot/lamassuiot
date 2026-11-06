package x509engines

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"go.mozilla.org/pkcs7"
)

const (
	defaultRelatedCertMaxAge = 5 * time.Minute
	relatedCertFetchTimeout  = 10 * time.Second
	maxRelatedCertSize       = 1 << 20
)

// id-aa-relatedCertRequest, RFC 9763
var oidRelatedCertRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 60}

// resolveRelatedCertificate retrieves the certificate requested by the CSR's relatedCertRequest attribute and verifies the attribute.
func resolveRelatedCertificate(ctx context.Context, csr *x509.CertificateRequest, now time.Time, policy models.IssuanceProfileRelatedCertificate) (*x509.Certificate, error) {
	attr, err := x509.ParseRelatedCertRequestAttribute(csr)
	if err != nil {
		return nil, err
	}

	related, err := retrieveRelatedCertificate(ctx, attr, policy.AllowedHosts)
	if err != nil {
		return nil, err
	}

	if err := attr.Verify(related, now, relatedCertAttributeMaxAge(policy)); err != nil {
		return nil, err
	}
	return related, nil
}

// retrieveRelatedCertificate returns the first related certificate that can be retrieved from the attribute's URIs.
func retrieveRelatedCertificate(ctx context.Context, attr *x509.RelatedCertRequestAttribute, allowedHosts []string) (*x509.Certificate, error) {
	var errs []error
	for _, uri := range attr.LocationInfo {
		relatedDER, err := fetchRelatedCertificate(ctx, uri, allowedHosts)
		if err == nil {
			var related *x509.Certificate
			if related, err = x509.ParseCertificate(relatedDER); err == nil {
				return related, nil
			}
		}
		errs = append(errs, fmt.Errorf("%s: %w", uri, err))
	}
	return nil, fmt.Errorf("could not retrieve the related certificate: %w", errors.Join(errs...))
}

func relatedCertAttributeMaxAge(policy models.IssuanceProfileRelatedCertificate) time.Duration {
	if policy.MaxAge <= 0 {
		return defaultRelatedCertMaxAge
	}
	return time.Duration(policy.MaxAge)
}

func hasRelatedCertRequest(csr *x509.CertificateRequest) bool {
	var tbs struct {
		Version       int
		Subject       asn1.RawValue
		PublicKey     asn1.RawValue
		RawAttributes []asn1.RawValue `asn1:"tag:0"`
	}
	if _, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &tbs); err != nil {
		return false
	}

	for _, rawAttr := range tbs.RawAttributes {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue
		}
		if _, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err == nil && attr.Type.Equal(oidRelatedCertRequest) {
			return true
		}
	}
	return false
}

func fetchRelatedCertificate(ctx context.Context, uri string, allowedHosts []string) ([]byte, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "data":
		payload, err := decodeDataURI(uri)
		if err != nil {
			return nil, err
		}
		return parsePKCS7Certificate(payload)
	case "http", "https":
		if !slices.Contains(allowedHosts, u.Hostname()) {
			return nil, fmt.Errorf("host %q is not allowed", u.Hostname())
		}
		payload, err := httpGetRelatedCert(ctx, uri)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(payload)
		if err != nil {
			return nil, err
		}
		return cert.Raw, nil
	default:
		return nil, fmt.Errorf("unsupported URI scheme %q", u.Scheme)
	}
}

func decodeDataURI(uri string) ([]byte, error) {
	meta, data, found := strings.Cut(strings.TrimPrefix(uri, "data:"), ",")
	if !found || !strings.HasSuffix(meta, ";base64") {
		return nil, errors.New("only base64 data URIs are supported")
	}
	return base64.StdEncoding.DecodeString(data)
}

func httpGetRelatedCert(ctx context.Context, uri string) ([]byte, error) {
	client := &http.Client{
		Timeout:       relatedCertFetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRelatedCertSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRelatedCertSize {
		return nil, errors.New("response is too large")
	}
	return body, nil
}

func parsePKCS7Certificate(payload []byte) ([]byte, error) {
	p7, err := pkcs7.Parse(payload)
	if err != nil {
		return nil, err
	}
	if len(p7.Certificates) == 0 {
		return nil, errors.New("PKCS#7 structure contains no certificates")
	}
	return p7.Certificates[0].Raw, nil
}
