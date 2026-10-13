//go:build !noaws

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/fs-storage/s3"
)

func init() {
	s3.Register()
}
