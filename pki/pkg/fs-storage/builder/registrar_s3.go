//go:build !noaws

package builder

import (
	"github.com/lamassuiot/lamassuiot/pki/v3/engines/fs-storage/s3"
)

func init() {
	s3.Register()
}
