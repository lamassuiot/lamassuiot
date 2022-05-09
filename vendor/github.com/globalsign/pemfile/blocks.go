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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

var (
	// ErrNotFound indicates that no PEM block was found at the beginning of
	// a file.
	ErrNotFound = errors.New("no PEM block found in file")

	// ErrTrailingData indicates that a file contains trailing data after one
	// or more PEM blocks.
	ErrTrailingData = errors.New("trailing data in file")
)

// ReadBlock reads a PEM block from a file. An error is returned if the
// file is empty, or if it contains any data other than a single PEM block.
func ReadBlock(filename string) (*pem.Block, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(b)
	if block == nil {
		return nil, ErrNotFound
	}
	if len(rest) > 0 {
		return nil, ErrTrailingData
	}

	return block, nil
}

// ReadBlocks reads a slice of PEM blocks from a file. An error is returned
// if the file is empty, or if it contains any data other than a sequence of PEM
// blocks.
func ReadBlocks(filename string) ([]*pem.Block, error) {
	rest, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var blocks = []*pem.Block{}

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(blocks) == 0 {
				return nil, ErrNotFound
			}

			return nil, ErrTrailingData
		}
		blocks = append(blocks, block)
	}

	if len(blocks) == 0 {
		return nil, ErrNotFound
	}

	return blocks, nil
}

// WriteBlock writes a PEM block.
func WriteBlock(w io.Writer, block *pem.Block) error {
	if _, err := w.Write(pem.EncodeToMemory(block)); err != nil {
		return fmt.Errorf("failed to write PEM block: %w", err)
	}

	return nil
}

// WriteBlocks writes a slice of PEM blocks.
func WriteBlocks(w io.Writer, blocks []*pem.Block) error {
	for _, block := range blocks {
		if err := WriteBlock(w, block); err != nil {
			return err
		}
	}

	return nil
}

// IsType returns an error if the type of a PEM block is not one of the
// provided values.
func IsType(block *pem.Block, want ...string) error {
	for _, t := range want {
		if block.Type == t {
			return nil
		}
	}

	var builder strings.Builder
	for i, t := range want {
		if i == 0 {
			builder.WriteString(fmt.Sprintf("%q", t))
		} else if i == len(want)-1 {
			builder.WriteString(fmt.Sprintf(" or %q", t))
		} else {
			builder.WriteString(fmt.Sprintf(", %q", t))
		}
	}

	return fmt.Errorf("got PEM block with type %q, expected %s", block.Type, builder.String())
}
