//go:build !noaws

package builder

import (
	"github.com/lamassuiot/lamassuiot/engines/fs-storage/s3/v3"
)

func init() {
	s3.Register()
}
