//go:build experimental
// +build experimental

package builder

import (
	"github.com/lamassuiot/lamassuiot/v3/engines/storage/sqlite"
)

func init() {
	sqlite.Register()
}
