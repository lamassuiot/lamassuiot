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
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	pkcs8PrivateKeyPEMType = "PRIVATE KEY"
	pkcs1PrivateKeyPEMType = "RSA PRIVATE KEY"
	ecPrivateKeyPEMType    = "EC PRIVATE KEY"
	pkixPublicKeyPEMType   = "PUBLIC KEY"
	pkcs1PublicKeyPEMType  = "RSA PUBLIC KEY"
)

// ReadPrivateKey reads a single private key. PKCS1 RSA private keys, SEC1 EC
// private keys, and PKCS8 RSA and EC private keys are supported.
func ReadPrivateKey(filename string) (interface{}, error) {
	block, err := ReadBlock(filename)
	if err != nil {
		return nil, err
	}

	return parsePrivateKeyBlock(block)
}

// ReadPrivateKeyWithPasswordFunc reads a single private key which may be in
// an encrypted PEM block. If it is, decryption is attemped with a password
// returned by the provided function. The two arguments to the function are
// a description of the type of credential (e.g. "password", "PIN") and a
// description of the target of the credential (e.g. "private key", "HSM").
// The function should return an error if the credential cannot be retrieved.
// If pwfunc is nil and the PEM block is encrypted, a password will be
// requested from the terminal.
func ReadPrivateKeyWithPasswordFunc(filename string, pwfunc func(string, string) ([]byte, error)) (interface{}, error) {
	block, err := ReadBlock(filename)
	if err != nil {
		return nil, err
	}

	if x509.IsEncryptedPEMBlock(block) {
		if pwfunc == nil {
			pwfunc = passwordFromTerminal
		}

		pass, err := pwfunc("passphrase", "private key")
		if err != nil {
			return nil, err
		}

		block.Bytes, err = x509.DecryptPEMBlock(block, pass)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt PEM block: %w", err)
		}
	}

	return parsePrivateKeyBlock(block)
}

// ReadPublicKey reads a single public key. PKCS1 RSA RSA public keys, and
// PKIX RSA and EC public keys are supported.
func ReadPublicKey(filename string) (interface{}, error) {
	block, err := ReadBlock(filename)
	if err != nil {
		return nil, err
	}

	if err := IsType(block, pkixPublicKeyPEMType, pkcs1PublicKeyPEMType); err != nil {
		return nil, err
	}

	var key interface{}

	switch block.Type {
	case pkixPublicKeyPEMType:
		key, err = x509.ParsePKIXPublicKey(block.Bytes)

	case pkcs1PublicKeyPEMType:
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return key, nil
}

// parsePrivateKeyBlock parses a private key in an (unencrypted) PEM block.
func parsePrivateKeyBlock(block *pem.Block) (interface{}, error) {
	err := IsType(block, pkcs8PrivateKeyPEMType, pkcs1PrivateKeyPEMType, ecPrivateKeyPEMType)
	if err != nil {
		return nil, err
	}

	var key interface{}

	switch block.Type {
	case pkcs8PrivateKeyPEMType:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)

	case pkcs1PrivateKeyPEMType:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)

	case ecPrivateKeyPEMType:
		key, err = x509.ParseECPrivateKey(block.Bytes)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}

// passwordFromTerminal prompts for a password at the terminal.
func passwordFromTerminal(cred, target string) ([]byte, error) {
	// Open the (POSIX standard) /dev/tty to ensure we're reading from and
	// writing to an actual terminal.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open terminal: %w", err)
	}

	tty.Write([]byte(fmt.Sprintf("Enter %s for %s: ", cred, target)))
	pass, err := terminal.ReadPassword(int(tty.Fd()))
	tty.Write([]byte("\n"))

	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	return pass, nil
}
