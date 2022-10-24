/*
Copyright (c) 2020 GMO GlobalSign, Inc.
Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at
https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"

	"go.mozilla.org/pkcs7"
)

type MultipartPart struct {
	ContentType string
	Data        interface{}
}

func ReadAllBase64Response(r io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode HTTP response body: %w", err)
	}

	return []byte(decoded), nil
}

// encodePKCS7CertsOnly encodes a slice of certificates as a PKCS#7 degenerate
// "certs-only" response.
func encodePKCS7CertsOnly(certs []*x509.Certificate) ([]byte, error) {
	var cb []byte
	for _, cert := range certs {
		cb = append(cb, cert.Raw...)
	}
	return pkcs7.DegenerateCertificate(cb)
}

// decodePKCS7CertsOnly decodes a PKCS#7 degenerate "certs-only" response and
// returns the certificate(s) it contains.
func DecodePKCS7CertsOnly(b []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(b)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}
func ReadCertResponse(r io.Reader) ([]*x509.Certificate, error) {
	p7, err := ReadAllBase64Response(r)
	if err != nil {
		return nil, err
	}

	certs, err := DecodePKCS7CertsOnly(p7)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS7: %w", err)
	}
	return certs, nil
}

// breakLines inserts a CRLF line break in the provided slice of bytes every n
// bytes, including a terminating CRLF for the last line.
func breakLines(b []byte, n int) []byte {
	crlf := []byte{'\r', '\n'}
	initialLen := len(b)

	// Just return a terminating CRLF if the input is empty.
	if initialLen == 0 {
		return crlf
	}

	// Allocate a buffer with suitable capacity to minimize allocations.
	buf := bytes.NewBuffer(make([]byte, 0, initialLen+((initialLen/n)+1)*2))

	// Split input into CRLF-terminated lines.
	for {
		lineLen := len(b)
		if lineLen == 0 {
			break
		} else if lineLen > n {
			lineLen = n
		}

		buf.Write(b[0:lineLen])
		b = b[lineLen:]
		buf.Write(crlf)
	}

	return buf.Bytes()
}

func EncodeMultiPart(boundary string, parts []MultipartPart) (*bytes.Buffer, string, error) {
	buf := bytes.NewBuffer([]byte{})
	w := multipart.NewWriter(buf)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, "", fmt.Errorf("failed to set multipart writer boundary: %w", err)
	}

	for _, part := range parts {
		var data []byte
		var err error

		switch t := part.Data.(type) {
		case []*x509.Certificate:
			data, err = encodePKCS7CertsOnly(t)
			if err != nil {
				return nil, "", err
			}

		case *x509.Certificate:
			data, err = encodePKCS7CertsOnly([]*x509.Certificate{t})
			if err != nil {
				return nil, "", err
			}

		case *x509.CertificateRequest:
			data = t.Raw

		case []byte:
			data = t

		default:
			return nil, "", fmt.Errorf("unexpected multipart part body type: %T", t)
		}

		v := textproto.MIMEHeader{}
		v.Add("Content-Type", part.ContentType)
		v.Add("Content-Transfer-Encoding", "base64")
		data = []byte(base64.StdEncoding.EncodeToString(data))

		pw, err := w.CreatePart(v)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create multipart writer part: %w", err)
		}

		if _, err := pw.Write(data); err != nil {
			return nil, "", fmt.Errorf("failed to write to multipart writer: %w", err)
		}
	}

	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	return buf, fmt.Sprintf("%s; %s=%s", "multipart/mixed", "boundary", boundary), nil
}

func WriteResponse(w http.ResponseWriter, contentType string, encode bool, obj interface{}) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	var body []byte
	var err error

	switch t := obj.(type) {
	case []*x509.Certificate:
		body, err = encodePKCS7CertsOnly(t)

	case *x509.Certificate:
		body, err = encodePKCS7CertsOnly([]*x509.Certificate{t})

	case []byte:
		body, err = t, nil
	}

	if err != nil {
		EncodeError(context.Background(), err, w)
		return
	}

	if encode {
		w.Header().Set("Content-Transfer-Encoding", "base64")
		body = []byte(base64.StdEncoding.EncodeToString(body))
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
