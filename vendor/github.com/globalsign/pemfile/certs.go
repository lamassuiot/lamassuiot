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
	certPEMType = "CERTIFICATE"
)

// ReadCert reads an X.509 certificate.
func ReadCert(filename string) (*x509.Certificate, error) {
	block, err := ReadBlock(filename)
	if err != nil {
		return nil, err
	}

	if err := IsType(block, certPEMType); err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// ReadCerts reads one or more X.509 certificates.
func ReadCerts(filename string) ([]*x509.Certificate, error) {
	blocks, err := ReadBlocks(filename)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	for _, block := range blocks {
		if err := IsType(block, certPEMType); err != nil {
			return nil, err
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// WriteCert writes an X.509 certificate.
func WriteCert(w io.Writer, cert *x509.Certificate) error {
	return WriteBlock(w, &pem.Block{
		Type:  certPEMType,
		Bytes: cert.Raw,
	})
}

// WriteCerts writes one or more X.509 certificates.
func WriteCerts(w io.Writer, certs []*x509.Certificate) error {
	for _, cert := range certs {
		if err := WriteCert(w, cert); err != nil {
			return err
		}
	}

	return nil
}
