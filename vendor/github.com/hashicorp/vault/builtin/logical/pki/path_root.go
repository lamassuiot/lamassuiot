package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/hashicorp/vault/sdk/helper/certutil"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathGenerateRoot(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "root/generate/" + framework.GenericNameRegex("exported"),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCAGenerateRoot,
				// Read more about why these flags are set in backend.go
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathGenerateRootHelpSyn,
		HelpDescription: pathGenerateRootHelpDesc,
	}

	ret.Fields = addCACommonFields(map[string]*framework.FieldSchema{})
	ret.Fields = addCAKeyGenerationFields(ret.Fields)
	ret.Fields = addCAIssueFields(ret.Fields)

	return ret
}

func pathDeleteRoot(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathCADeleteRoot,
				// Read more about why these flags are set in backend.go
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathDeleteRootHelpSyn,
		HelpDescription: pathDeleteRootHelpDesc,
	}

	return ret
}

func pathSignIntermediate(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "root/sign-intermediate",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCASignIntermediate,
			},
		},

		HelpSynopsis:    pathSignIntermediateHelpSyn,
		HelpDescription: pathSignIntermediateHelpDesc,
	}

	ret.Fields = addCACommonFields(map[string]*framework.FieldSchema{})
	ret.Fields = addCAIssueFields(ret.Fields)

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM-format CSR to be signed.`,
	}

	ret.Fields["use_csr_values"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: false,
		Description: `If true, then:
1) Subject information, including names and alternate
names, will be preserved from the CSR rather than
using values provided in the other parameters to
this path;
2) Any key usages requested in the CSR will be
added to the basic set of key usages used for CA
certs signed by this path; for instance,
the non-repudiation flag;
3) Extensions requested in the CSR will be copied
into the issued certificate.`,
	}

	return ret
}

func pathSignSelfIssued(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "root/sign-self-issued",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCASignSelfIssued,
			},
		},

		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Type:        framework.TypeString,
				Description: `PEM-format self-issued certificate to be signed.`,
			},
			"require_matching_certificate_algorithms": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: `If true, require the public key algorithm of the signer to match that of the self issued certificate.`,
			},
		},

		HelpSynopsis:    pathSignSelfIssuedHelpSyn,
		HelpDescription: pathSignSelfIssuedHelpDesc,
	}

	return ret
}

func (b *backend) pathCADeleteRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, "config/ca_bundle")
}

func (b *backend) pathCAGenerateRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error

	entry, err := req.Storage.Get(ctx, "config/ca_bundle")
	if err != nil {
		return nil, err
	}
	if entry != nil {
		resp := &logical.Response{}
		resp.AddWarning(fmt.Sprintf("Refusing to generate a root certificate over an existing root certificate. "+
			"If you really want to destroy the original root certificate, please issue a delete against %s root.", req.MountPoint))
		return resp, nil
	}

	exported, format, role, errorResp := b.getGenerationParams(ctx, data, req.MountPoint)
	if errorResp != nil {
		return errorResp, nil
	}

	maxPathLengthIface, ok := data.GetOk("max_path_length")
	if ok {
		maxPathLength := maxPathLengthIface.(int)
		role.MaxPathLength = &maxPathLength
	}

	input := &inputBundle{
		req:     req,
		apiData: data,
		role:    role,
	}
	parsedBundle, err := generateCert(ctx, b, input, nil, true, b.Backend.GetRandomReader())
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		default:
			return nil, err
		}
	}

	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw cert bundle to cert bundle: %w", err)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"expiration":    int64(parsedBundle.Certificate.NotAfter.Unix()),
			"serial_number": cb.SerialNumber,
		},
	}

	switch format {
	case "pem":
		resp.Data["certificate"] = cb.Certificate
		resp.Data["issuing_ca"] = cb.Certificate
		if exported {
			resp.Data["private_key"] = cb.PrivateKey
			resp.Data["private_key_type"] = cb.PrivateKeyType
		}

	case "pem_bundle":
		resp.Data["issuing_ca"] = cb.Certificate

		if exported {
			resp.Data["private_key"] = cb.PrivateKey
			resp.Data["private_key_type"] = cb.PrivateKeyType
			resp.Data["certificate"] = fmt.Sprintf("%s\n%s", cb.PrivateKey, cb.Certificate)
		} else {
			resp.Data["certificate"] = cb.Certificate
		}

	case "der":
		resp.Data["certificate"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
		resp.Data["issuing_ca"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
		if exported {
			resp.Data["private_key"] = base64.StdEncoding.EncodeToString(parsedBundle.PrivateKeyBytes)
			resp.Data["private_key_type"] = cb.PrivateKeyType
		}
	}

	if data.Get("private_key_format").(string) == "pkcs8" {
		err = convertRespToPKCS8(resp)
		if err != nil {
			return nil, err
		}
	}

	// Store it as the CA bundle
	entry, err = logical.StorageEntryJSON("config/ca_bundle", cb)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	// Also store it as just the certificate identified by serial number, so it
	// can be revoked
	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "certs/" + normalizeSerial(cb.SerialNumber),
		Value: parsedBundle.CertificateBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to store certificate locally: %w", err)
	}

	// For ease of later use, also store just the certificate at a known
	// location
	entry.Key = "ca"
	entry.Value = parsedBundle.CertificateBytes
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	// Build a fresh CRL
	err = buildCRL(ctx, b, req, true)
	if err != nil {
		return nil, err
	}

	if parsedBundle.Certificate.MaxPathLen == 0 {
		resp.AddWarning("Max path length of the generated certificate is zero. This certificate cannot be used to issue intermediate CA certificates.")
	}

	return resp, nil
}

func (b *backend) pathCASignIntermediate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error

	format := getFormat(data)
	if format == "" {
		return logical.ErrorResponse(
			`The "format" path parameter must be "pem" or "der"`,
		), nil
	}

	role := &roleEntry{
		OU:                        data.Get("ou").([]string),
		Organization:              data.Get("organization").([]string),
		Country:                   data.Get("country").([]string),
		Locality:                  data.Get("locality").([]string),
		Province:                  data.Get("province").([]string),
		StreetAddress:             data.Get("street_address").([]string),
		PostalCode:                data.Get("postal_code").([]string),
		TTL:                       time.Duration(data.Get("ttl").(int)) * time.Second,
		AllowLocalhost:            true,
		AllowAnyName:              true,
		AllowIPSANs:               true,
		AllowWildcardCertificates: new(bool),
		EnforceHostnames:          false,
		KeyType:                   "any",
		AllowedOtherSANs:          []string{"*"},
		AllowedSerialNumbers:      []string{"*"},
		AllowedURISANs:            []string{"*"},
		AllowExpirationPastCA:     true,
		NotAfter:                  data.Get("not_after").(string),
	}
	*role.AllowWildcardCertificates = true

	if cn := data.Get("common_name").(string); len(cn) == 0 {
		role.UseCSRCommonName = true
	}

	var caErr error
	signingBundle, caErr := fetchCAInfo(ctx, b, req)
	if caErr != nil {
		switch caErr.(type) {
		case errutil.UserError:
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"could not fetch the CA certificate (was one set?): %s", caErr)}
		default:
			return nil, errutil.InternalError{Err: fmt.Sprintf(
				"error fetching CA certificate: %s", caErr)}
		}
	}

	useCSRValues := data.Get("use_csr_values").(bool)

	maxPathLengthIface, ok := data.GetOk("max_path_length")
	if ok {
		maxPathLength := maxPathLengthIface.(int)
		role.MaxPathLength = &maxPathLength
	}

	input := &inputBundle{
		req:     req,
		apiData: data,
		role:    role,
	}
	parsedBundle, err := signCert(b, input, signingBundle, true, useCSRValues)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		default:
			return nil, errutil.InternalError{Err: fmt.Sprintf(
				"error signing cert: %s", err)}
		}
	}

	if err := parsedBundle.Verify(); err != nil {
		return nil, fmt.Errorf("verification of parsed bundle failed: %w", err)
	}

	signingCB, err := signingBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw signing bundle to cert bundle: %w", err)
	}

	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw cert bundle to cert bundle: %w", err)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"expiration":    int64(parsedBundle.Certificate.NotAfter.Unix()),
			"serial_number": cb.SerialNumber,
		},
	}

	if signingBundle.Certificate.NotAfter.Before(parsedBundle.Certificate.NotAfter) {
		resp.AddWarning("The expiration time for the signed certificate is after the CA's expiration time. If the new certificate is not treated as a root, validation paths with the certificate past the issuing CA's expiration time will fail.")
	}

	switch format {
	case "pem":
		resp.Data["certificate"] = cb.Certificate
		resp.Data["issuing_ca"] = signingCB.Certificate
		if cb.CAChain != nil && len(cb.CAChain) > 0 {
			resp.Data["ca_chain"] = cb.CAChain
		}

	case "pem_bundle":
		resp.Data["certificate"] = cb.ToPEMBundle()
		resp.Data["issuing_ca"] = signingCB.Certificate
		if cb.CAChain != nil && len(cb.CAChain) > 0 {
			resp.Data["ca_chain"] = cb.CAChain
		}

	case "der":
		resp.Data["certificate"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
		resp.Data["issuing_ca"] = base64.StdEncoding.EncodeToString(signingBundle.CertificateBytes)

		var caChain []string
		for _, caCert := range parsedBundle.CAChain {
			caChain = append(caChain, base64.StdEncoding.EncodeToString(caCert.Bytes))
		}
		if caChain != nil && len(caChain) > 0 {
			resp.Data["ca_chain"] = cb.CAChain
		}
	}

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "certs/" + normalizeSerial(cb.SerialNumber),
		Value: parsedBundle.CertificateBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to store certificate locally: %w", err)
	}

	if parsedBundle.Certificate.MaxPathLen == 0 {
		resp.AddWarning("Max path length of the signed certificate is zero. This certificate cannot be used to issue intermediate CA certificates.")
	}

	return resp, nil
}

func (b *backend) pathCASignSelfIssued(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error

	certPem := data.Get("certificate").(string)
	block, _ := pem.Decode([]byte(certPem))
	if block == nil || len(block.Bytes) == 0 {
		return logical.ErrorResponse("certificate could not be PEM-decoded"), nil
	}
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error parsing certificate: %s", err)), nil
	}
	if len(certs) != 1 {
		return logical.ErrorResponse(fmt.Sprintf("%d certificates found in PEM file, expected 1", len(certs))), nil
	}

	cert := certs[0]
	if !cert.IsCA {
		return logical.ErrorResponse("given certificate is not a CA certificate"), nil
	}
	if !reflect.DeepEqual(cert.Issuer, cert.Subject) {
		return logical.ErrorResponse("given certificate is not self-issued"), nil
	}

	var caErr error
	signingBundle, caErr := fetchCAInfo(ctx, b, req)
	if caErr != nil {
		switch caErr.(type) {
		case errutil.UserError:
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"could not fetch the CA certificate (was one set?): %s", caErr)}
		default:
			return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching CA certificate: %s", caErr)}
		}
	}

	signingCB, err := signingBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw signing bundle to cert bundle: %w", err)
	}

	urls := &certutil.URLEntries{}
	if signingBundle.URLs != nil {
		urls = signingBundle.URLs
	}
	cert.IssuingCertificateURL = urls.IssuingCertificates
	cert.CRLDistributionPoints = urls.CRLDistributionPoints
	cert.OCSPServer = urls.OCSPServers

	// If the requested signature algorithm isn't the same as the signing certificate, and
	// the user has requested a cross-algorithm signature, reset the template's signing algorithm
	// to that of the signing key
	signingPubType, signingAlgorithm, err := publicKeyType(signingBundle.Certificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error determining signing certificate algorithm type: %e", err)
	}
	certPubType, _, err := publicKeyType(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error determining template algorithm type: %e", err)
	}

	if signingPubType != certPubType {
		b, ok := data.GetOk("require_matching_certificate_algorithms")
		if !ok || !b.(bool) {
			cert.SignatureAlgorithm = signingAlgorithm
		} else {
			return nil, fmt.Errorf("signing certificate's public key algorithm (%s) does not match submitted certificate's (%s), and require_matching_certificate_algorithms is true",
				signingPubType.String(), certPubType.String())
		}
	}

	newCert, err := x509.CreateCertificate(rand.Reader, cert, signingBundle.Certificate, cert.PublicKey, signingBundle.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error signing self-issued certificate: %w", err)
	}
	if len(newCert) == 0 {
		return nil, fmt.Errorf("nil cert was created when signing self-issued certificate")
	}
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCert,
	})

	return &logical.Response{
		Data: map[string]interface{}{
			"certificate": strings.TrimSpace(string(pemCert)),
			"issuing_ca":  signingCB.Certificate,
		},
	}, nil
}

// Adapted from similar code in https://github.com/golang/go/blob/4a4221e8187189adcc6463d2d96fe2e8da290132/src/crypto/x509/x509.go#L1342,
// may need to be updated in the future.
func publicKeyType(pub crypto.PublicKey) (pubType x509.PublicKeyAlgorithm, sigAlgo x509.SignatureAlgorithm, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = x509.RSA
		sigAlgo = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		pubType = x509.ECDSA
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			sigAlgo = x509.ECDSAWithSHA256
		case elliptic.P384():
			sigAlgo = x509.ECDSAWithSHA384
		case elliptic.P521():
			sigAlgo = x509.ECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}
	case ed25519.PublicKey:
		pubType = x509.Ed25519
		sigAlgo = x509.PureEd25519
	default:
		err = errors.New("x509: only RSA, ECDSA and Ed25519 keys supported")
	}
	return
}

const pathGenerateRootHelpSyn = `
Generate a new CA certificate and private key used for signing.
`

const pathGenerateRootHelpDesc = `
See the API documentation for more information.
`

const pathDeleteRootHelpSyn = `
Deletes the root CA key to allow a new one to be generated.
`

const pathDeleteRootHelpDesc = `
See the API documentation for more information.
`

const pathSignIntermediateHelpSyn = `
Issue an intermediate CA certificate based on the provided CSR.
`

const pathSignIntermediateHelpDesc = `
see the API documentation for more information.
`

const pathSignSelfIssuedHelpSyn = `
Signs another CA's self-issued certificate.
`

const pathSignSelfIssuedHelpDesc = `
Signs another CA's self-issued certificate. This is most often used for rolling roots; unless you know you need this you probably want to use sign-intermediate instead.

Note that this is a very privileged operation and should be extremely restricted in terms of who is allowed to use it. All values will be taken directly from the incoming certificate and only verification that it is self-issued will be performed.

Configured URLs for CRLs/OCSP/etc. will be copied over and the issuer will be this mount's CA cert. Other than that, all other values will be used verbatim.
`
