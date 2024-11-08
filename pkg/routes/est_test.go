package routes

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	smock "github.com/lamassuiot/lamassuiot/v2/core/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestEnrollReenroll(t *testing.T) {
	gin.SetMode(gin.TestMode)

	csr, err := os.ReadFile("../helpers/testdata/samplecsr.pem")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	csrDERBlock, _ := pem.Decode(csr)

	tests := []struct {
		name           string
		url            string
		contentType    string
		accept         string
		body           string
		expectedStatus int
		expectedError  string
		mockSetup      func(*smock.MockESTService)
		resultCheck    func(*testing.T, *smock.MockESTService, *http.Response)
	}{
		{
			name:           "Enroll success pkcs7",
			url:            "/.well-known/est/aps/simpleenroll",
			accept:         "",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusOK,
			mockSetup: func(m *smock.MockESTService) {
				m.On("Enroll", mock.Anything, mock.Anything, "aps").Return(&x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				assert.Equal(t, "application/pkcs7-mime; smime-type=certs-only", res.Header.Get("Content-Type"))
				m.AssertExpectations(t)
			},
		},
		{
			name:           "Enroll error without aps",
			url:            "/.well-known/est/simpleenroll",
			accept:         "",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Field validation for 'APS'",
			mockSetup: func(m *smock.MockESTService) {
				m.On("Enroll", mock.Anything, mock.Anything, "aps").Return(&x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				m.AssertNotCalled(t, "Enroll")
			},
		},
		{
			name:           "Enroll success pem",
			url:            "/.well-known/est/aps/simpleenroll",
			accept:         "application/x-pem-file",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusOK,
			mockSetup: func(m *smock.MockESTService) {
				m.On("Enroll", mock.Anything, mock.Anything, "aps").Return(&x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				assert.Equal(t, "application/x-pem-file", res.Header.Get("Content-Type"))
				m.AssertExpectations(t)
			},
		},
		{
			name:           "ReEnroll success pkcs7",
			url:            "/.well-known/est/aps/simplereenroll",
			accept:         "",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusOK,
			mockSetup: func(m *smock.MockESTService) {
				m.On("Reenroll", mock.Anything, mock.Anything, "aps").Return(&x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				assert.Equal(t, "application/pkcs7-mime; smime-type=certs-only", res.Header.Get("Content-Type"))
				m.AssertExpectations(t)
			},
		},
		{
			name:           "ReEnroll error without aps",
			url:            "/.well-known/est/simplereenroll",
			accept:         "",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Field validation for 'APS'",
			mockSetup: func(m *smock.MockESTService) {
				m.On("Enroll", mock.Anything, mock.Anything, "aps").Return(&x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				m.AssertNotCalled(t, "Enroll")
			},
		},
		{
			name:           "ReEnroll success pem",
			url:            "/.well-known/est/aps/simplereenroll",
			accept:         "application/x-pem-file",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusOK,
			mockSetup: func(m *smock.MockESTService) {
				m.On("Reenroll", mock.Anything, mock.Anything, "aps").Return(&x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				assert.Equal(t, "application/x-pem-file", res.Header.Get("Content-Type"))
				m.AssertExpectations(t)
			},
		},
		{
			name:           "Invalid content type",
			url:            "/.well-known/est/aps/simpleenroll",
			accept:         "",
			contentType:    "application/json",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "content-type must be application/pkcs10",
			mockSetup:      func(m *smock.MockESTService) {},
			resultCheck:    func(t *testing.T, m *smock.MockESTService, res *http.Response) {},
		},
		{
			name:           "Enroll error",
			url:            "/.well-known/est/aps/simpleenroll",
			accept:         "",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "enroll error",
			mockSetup: func(m *smock.MockESTService) {
				m.On("Enroll", mock.Anything, mock.Anything, "aps").Return((*x509.Certificate)(nil), errors.New("enroll error"))
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {},
		},
		{
			name:           "Invalid content type",
			url:            "/.well-known/est/aps/simplereenroll",
			accept:         "",
			contentType:    "application/json",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "content-type must be application/pkcs10",
			mockSetup:      func(m *smock.MockESTService) {},
			resultCheck:    func(t *testing.T, m *smock.MockESTService, res *http.Response) {},
		},
		{
			name:           "Enroll error",
			url:            "/.well-known/est/aps/simplereenroll",
			accept:         "",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "reenroll error",
			mockSetup: func(m *smock.MockESTService) {
				m.On("Reenroll", mock.Anything, mock.Anything, "aps").Return((*x509.Certificate)(nil), errors.New("reenroll error"))
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(smock.MockESTService)
			tt.mockSetup(mockSvc)

			r := gin.Default()
			baseGrp := r.Group(("/"))
			NewESTHttpRoutes(nil, baseGrp, mockSvc)

			req, _ := http.NewRequest(http.MethodPost, tt.url, bytes.NewBufferString(tt.body))
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
			tt.resultCheck(t, mockSvc, w.Result())
		})
	}
}

func TestServerKeyGen(t *testing.T) {
	gin.SetMode(gin.TestMode)

	csr, err := os.ReadFile("../helpers/testdata/samplecsr.pem")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	csrDERBlock, _ := pem.Decode(csr)

	tests := []struct {
		name           string
		url            string
		contentType    string
		accept         string
		body           string
		expectedStatus int
		expectedError  string
		mockSetup      func(*smock.MockESTService)
		resultCheck    func(*testing.T, *smock.MockESTService, *http.Response)
	}{
		{
			name:           "ServerKeyGen success",
			url:            "/.well-known/est/aps/serverkeygen",
			accept:         "",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusOK,
			mockSetup: func(m *smock.MockESTService) {
				privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				m.On("ServerKeyGen", mock.Anything, mock.Anything, "aps").Return(&x509.Certificate{}, privkey, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				assert.Equal(t, "multipart/mixed; boundary=estServerLamassuBoundary", res.Header.Get("Content-Type"))

				_, params, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
				mr := multipart.NewReader(res.Body, params["boundary"])
				part, err := mr.NextPart()
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				assert.Equal(t, "application/pkcs8", part.Header.Get("Content-Type"))

				part, err = mr.NextPart()
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				assert.Equal(t, "application/pkcs7-mime; smime-type=certs-only", part.Header.Get("Content-Type"))

				m.AssertExpectations(t)
			},
		},
		{
			name:           "ServerKeyGen error without aps",
			url:            "/.well-known/est/serverkeygen",
			accept:         "",
			contentType:    "application/pkcs10",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Field validation for 'APS'",
			mockSetup: func(m *smock.MockESTService) {
				privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				m.On("ServerKeyGen", mock.Anything, mock.Anything, "aps").Return(&x509.Certificate{}, privkey, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				m.AssertNotCalled(t, "ServerKeyGen")
			},
		},
		{
			name:           "Invalid content type",
			url:            "/.well-known/est/aps/serverkeygen",
			accept:         "",
			contentType:    "application/json",
			body:           base64.StdEncoding.EncodeToString(csrDERBlock.Bytes),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "content-type must be application/pkcs10",
			mockSetup:      func(m *smock.MockESTService) {},
			resultCheck:    func(t *testing.T, m *smock.MockESTService, res *http.Response) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(smock.MockESTService)
			tt.mockSetup(mockSvc)

			r := gin.Default()
			baseGrp := r.Group(("/"))
			NewESTHttpRoutes(nil, baseGrp, mockSvc)

			req, _ := http.NewRequest(http.MethodPost, tt.url, bytes.NewBufferString(tt.body))
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
			tt.resultCheck(t, mockSvc, w.Result())
		})
	}
}

func TestCACerts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		url            string
		contentType    string
		accept         string
		expectedStatus int
		expectedError  string
		mockSetup      func(*smock.MockESTService)
		resultCheck    func(*testing.T, *smock.MockESTService, *http.Response)
	}{
		{
			name:           "cacerts success",
			url:            "/.well-known/est/aps/cacerts",
			accept:         "",
			contentType:    "",
			expectedStatus: http.StatusOK,
			mockSetup: func(m *smock.MockESTService) {
				m.On("CACerts", mock.Anything, "aps").Return([]*x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				assert.Equal(t, "application/pkcs7-mime; smime-type=certs-only", res.Header.Get("Content-Type"))
				m.AssertExpectations(t)
			},
		},
		{
			name:           "cacerts success pem",
			url:            "/.well-known/est/aps/cacerts",
			accept:         "application/x-pem-file",
			contentType:    "",
			expectedStatus: http.StatusOK,
			mockSetup: func(m *smock.MockESTService) {
				m.On("CACerts", mock.Anything, "aps").Return([]*x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				assert.Equal(t, "application/x-pem-file", res.Header.Get("Content-Type"))
				m.AssertExpectations(t)
			},
		},
		{
			name:           "cacerts error without aps",
			url:            "/.well-known/est/cacerts",
			accept:         "",
			contentType:    "",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Field validation for 'APS'",
			mockSetup: func(m *smock.MockESTService) {
				m.On("CACerts", mock.Anything, "aps").Return([]*x509.Certificate{}, nil)
			},
			resultCheck: func(t *testing.T, m *smock.MockESTService, res *http.Response) {
				m.AssertNotCalled(t, "CACerts")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(smock.MockESTService)
			tt.mockSetup(mockSvc)

			r := gin.Default()
			baseGrp := r.Group(("/"))
			NewESTHttpRoutes(nil, baseGrp, mockSvc)

			req, _ := http.NewRequest(http.MethodGet, tt.url, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
			tt.resultCheck(t, mockSvc, w.Result())
		})
	}
}
