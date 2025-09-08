package assemblers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
)

func getCertificateTemplate(csr x509.CertificateRequest, ec x509.Certificate) x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, _ := rand.Int(rand.Reader, serialNumberLimit)

	return x509.Certificate{
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		AuthorityKeyId:     ec.SubjectKeyId,
		SerialNumber:       sn,
		Issuer:             ec.Subject,
		Subject:            csr.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour * 24),
		ExtraExtensions:    []pkix.Extension{},
		OCSPServer: []string{
			fmt.Sprintf("https://%s/api/va/ocsp", "localhost"),
		},
		CRLDistributionPoints: []string{
			fmt.Sprintf("https://%s/api/va/crl/%s", "localhost", string(ec.SubjectKeyId)),
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsage(x509.ExtKeyUsageOCSPSigning),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func TestImportCAWithNoRequestAndDifferentCNError(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	externalCACert, privateKey, err := helpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ExternalCA")
	if err != nil {
		t.Fatalf("could not generate external CA: %s", err)
	}

	requestedCACSR, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	csr := x509.CertificateRequest(requestedCACSR.CSR)

	certificateTemplate := getCertificateTemplate(csr, *externalCACert)
	certificateTemplate.IsCA = true
	certificateTemplate.Subject.CommonName = "MyAlternateRequestedCA"

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, externalCACert, csr.PublicKey, privateKey.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("could not create the requested CA: %s", err)
	}

	requestedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatalf("could not parse the requested CA: %s", err)
	}

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "TestProfile",
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	rcert := models.X509Certificate(*requestedCertificate)
	_, err = serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: &rcert,
		CAType:        models.CertificateTypeRequested,
		ProfileID:     profile.ID,
	})
	assert.EqualError(t, err, "no pending CA Request can be found")
}

func TestImportCAWithNoCreatedRequest(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	externalCACert, privateKey, err := helpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ExternalCA")
	if err != nil {
		t.Fatalf("could not generate external CA: %s", err)
	}

	requestedCACSR, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	csr := x509.CertificateRequest(requestedCACSR.CSR)

	certificateTemplate := getCertificateTemplate(csr, *externalCACert)
	certificateTemplate.IsCA = true
	certificateTemplate.Subject.CommonName = "MyAlternateRequestedCA"

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, externalCACert, csr.PublicKey, privateKey.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("could not create the requested CA: %s", err)
	}

	requestedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatalf("could not parse the requested CA: %s", err)
	}

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "TestProfile",
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	rcert := models.X509Certificate(*requestedCertificate)
	_, err = serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: &rcert,
		CAType:        models.CertificateTypeRequested,
		ProfileID:     profile.ID,
	})
	assert.EqualError(t, err, "no pending CA Request can be found")
}

func TestImportCAWithNoRequestId(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	externalCACert, privateKey, err := helpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ExternalCA")
	if err != nil {
		t.Fatalf("could not generate external CA: %s", err)
	}

	ec := models.X509Certificate(*externalCACert)

	requestedCACSR, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	csr := x509.CertificateRequest(requestedCACSR.CSR)

	certificateTemplate := getCertificateTemplate(csr, *externalCACert)
	certificateTemplate.IsCA = true

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, externalCACert, csr.PublicKey, privateKey.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("could not create the requested CA: %s", err)
	}

	requestedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatalf("could not parse the requested CA: %s", err)
	}

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "TestProfile",
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	rcert := models.X509Certificate(*requestedCertificate)
	importedCertificate, err := serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: &rcert,
		CAType:        models.CertificateTypeRequested,
		ProfileID:     profile.ID,
	})
	if err != nil {
		t.Fatalf("could not import the requested CA: %s", err)
	}

	assert.Equal(t, importedCertificate.Certificate.Subject.CommonName, csr.Subject.CommonName)
	assert.Equal(t, importedCertificate.Certificate.Certificate.Issuer.CommonName, ec.Subject.CommonName)
}

func TestRequestCADoubleImportError(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	externalCACert, privateKey, err := helpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ExternalCA")
	if err != nil {
		t.Fatalf("could not generate external CA: %s", err)
	}

	ec := models.X509Certificate(*externalCACert)

	requestedCACSR, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	csr := x509.CertificateRequest(requestedCACSR.CSR)

	certificateTemplate := getCertificateTemplate(csr, *externalCACert)
	certificateTemplate.IsCA = true

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, externalCACert, csr.PublicKey, privateKey.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("could not create the requested CA: %s", err)
	}

	requestedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatalf("could not parse the requested CA: %s", err)
	}

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "TestProfile",
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	rcert := models.X509Certificate(*requestedCertificate)
	importedCertificate, err := serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: &rcert,
		CARequestID:   requestedCACSR.ID,
		CAType:        models.CertificateTypeRequested,
		ProfileID:     profile.ID,
	})
	if err != nil {
		t.Fatalf("could not import the requested CA: %s", err)
	}

	assert.Equal(t, importedCertificate.Certificate.Subject.CommonName, csr.Subject.CommonName)
	assert.Equal(t, importedCertificate.Certificate.Certificate.Issuer.CommonName, ec.Subject.CommonName)

	_, err = serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: &rcert,
		CARequestID:   requestedCACSR.ID,
		CAType:        models.CertificateTypeRequested,
		ProfileID:     profile.ID,
	})

	assert.EqualError(t, err, "CA Request is not pending")
}

func TestImportNonCACertError(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	externalCACert, privateKey, err := helpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ExternalCA")
	if err != nil {
		t.Fatalf("could not generate external CA: %s", err)
	}

	requestedCACSR, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	csr := x509.CertificateRequest(requestedCACSR.CSR)

	certificateTemplate := getCertificateTemplate(csr, *externalCACert)

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, externalCACert, csr.PublicKey, privateKey.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("could not create the requested CA: %s", err)
	}

	requestedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatalf("could not parse the requested CA: %s", err)
	}

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "TestProfile",
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	rcert := models.X509Certificate(*requestedCertificate)
	_, err = serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: &rcert,
		CARequestID:   requestedCACSR.ID,
		CAType:        models.CertificateTypeRequested,
		ProfileID:     profile.ID,
	})

	assert.EqualError(t, err, "CA certificate and CSR are not compatible - IsCA")

}

func TestImportUnexpectedCSRError(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	externalCACert, privateKey, err := helpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ExternalCA")
	if err != nil {
		t.Fatalf("could not generate external CA: %s", err)
	}

	requestedCACSR, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	unexpectedCACSR, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	csr := x509.CertificateRequest(unexpectedCACSR.CSR)

	certificateTemplate := getCertificateTemplate(csr, *externalCACert)
	certificateTemplate.IsCA = true

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, externalCACert, csr.PublicKey, privateKey.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("could not create the requested CA: %s", err)
	}

	requestedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatalf("could not parse the requested CA: %s", err)
	}

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "TestProfile",
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	rcert := models.X509Certificate(*requestedCertificate)
	_, err = serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: &rcert,
		CARequestID:   requestedCACSR.ID,
		CAType:        models.CertificateTypeRequested,
		ProfileID:     profile.ID,
	})

	assert.EqualError(t, err, "CA certificate and CSR are not compatible - Public Key")

}

func TestImportNonExistentRequest(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	externalCACert, _, err := helpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ExternalCA")
	if err != nil {
		t.Fatalf("could not generate external CA: %s", err)
	}

	ec := models.X509Certificate(*externalCACert)
	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "TestProfile",
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	_, err = serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: &ec,
		CARequestID:   "unknown",
		CAType:        models.CertificateTypeRequested,
		ProfileID:     profile.ID,
	})

	assert.EqualError(t, err, "CA Request not found")
}

func TestDeleteCARequest(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)

	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	requestedCACSR, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	retrievedReq, err := serverTest.CA.Service.GetCARequestByID(context.Background(), services.GetByIDInput{
		ID: requestedCACSR.ID,
	})
	if err != nil {
		t.Fatalf("could not retrieve the requested CA: %s", err)
	}
	assert.Equal(t, retrievedReq.ID, requestedCACSR.ID)
	assert.Equal(t, retrievedReq.Subject, requestedCACSR.Subject)
	assert.Equal(t, retrievedReq.KeyId, requestedCACSR.KeyId)
	assert.Equal(t, retrievedReq.CSR, requestedCACSR.CSR)
	assert.Equal(t, retrievedReq.Metadata, requestedCACSR.Metadata)
	assert.Equal(t, retrievedReq.EngineID, requestedCACSR.EngineID)
	assert.Equal(t, retrievedReq.KeyMetadata, requestedCACSR.KeyMetadata)
	assert.Equal(t, retrievedReq.Status, requestedCACSR.Status)

	requestedCACSR2, err := serverTest.CA.Service.RequestCACSR(context.Background(), services.RequestCAInput{
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "MyRequestedCA2"},
	})
	if err != nil {
		t.Fatalf("unexpected error. Could not request CA: %s", err)
	}

	var reqs []models.CACertificateRequest

	_, err = serverTest.CA.Service.GetCARequests(context.Background(), services.GetItemsInput[models.CACertificateRequest]{
		QueryParameters: nil,
		ExhaustiveRun:   false,
		ApplyFunc: func(req models.CACertificateRequest) {
			reqs = append(reqs, req)
		},
	})
	if err != nil {
		t.Fatalf("could not retrieve the requested CA: %s", err)
	}

	assert.Equal(t, len(reqs), 2)

	queryParams := resources.QueryParameters{
		NextBookmark: "",
		Filters:      []resources.FilterOption{},
		PageSize:     25,
	}

	queryParams.Filters = append(queryParams.Filters, resources.FilterOption{
		Field:           "subject_common_name",
		FilterOperation: resources.StringEqual,
		Value:           "MyRequestedCA",
	})

	reqs = []models.CACertificateRequest{}
	_, err = serverTest.CA.Service.GetCARequests(context.Background(), services.GetItemsInput[models.CACertificateRequest]{
		QueryParameters: &queryParams,
		ExhaustiveRun:   false,
		ApplyFunc: func(req models.CACertificateRequest) {
			reqs = append(reqs, req)
		},
	})
	if err != nil {
		t.Fatalf("could not retrieve the requested CA: %s", err)
	}

	assert.Equal(t, len(reqs), 1)

	err = serverTest.CA.Service.DeleteCARequestByID(context.Background(), services.GetByIDInput{
		ID: requestedCACSR2.ID,
	})
	if err != nil {
		t.Fatalf("could not delete the requested CA: %s", err)
	}

	_, err = serverTest.CA.Service.GetCARequestByID(context.Background(), services.GetByIDInput{
		ID: requestedCACSR2.ID,
	})
	assert.EqualError(t, err, "CA not found")

}
