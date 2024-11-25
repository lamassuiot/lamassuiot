//go:build experimental
// +build experimental

package builder

import (
	"github.com/lamassuiot/lamassuiot/engines/storage/sqlite/v3"
)

func init() {
	sqlite.Register()
}
