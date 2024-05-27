//go:build experimental
// +build experimental

package builder

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/sqlite"
)

func init() {
	sqlite.Register()
}
