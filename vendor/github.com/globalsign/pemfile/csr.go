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

package pemfile

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

const (
	csrPEMType    = "CERTIFICATE REQUEST"
	newCSRPEMType = "NEW CERTIFICATE REQUEST"
)

// ReadCSR reads a single PKCS#10 certificate signing request.
func ReadCSR(filename string) (*x509.CertificateRequest, error) {
	block, err := ReadBlock(filename)
	if err != nil {
		return nil, err
	}

	if err := IsType(block, csrPEMType, newCSRPEMType); err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	return csr, nil
}

// WriteCSR writes a PKCS#10 certificate signing request.
func WriteCSR(w io.Writer, csr *x509.CertificateRequest) error {
	return WriteBlock(w, &pem.Block{
		Type:  csrPEMType,
		Bytes: csr.Raw,
	})
}
