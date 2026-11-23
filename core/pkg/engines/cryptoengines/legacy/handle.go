package legacy

import (
	"crypto"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
)

// signerHandle is a private key loaded from a CryptoEngine: the crypto.Signer the engine returned, and the
// reference it was loaded with.
type signerHandle struct {
	ref cryptoengines.KeyRef
	crypto.Signer
}

var _ cryptoengines.Signer = (*signerHandle)(nil)

func (h *signerHandle) Ref() cryptoengines.KeyRef { return h.ref }
