package postgres

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/stretchr/testify/require"
)

func TestSignerErrorDistinguishesMissingKeyFromCertificate(t *testing.T) {
	for _, tc := range []struct {
		constraint string
		want       error
	}{
		{"crl_settings_signer_cert_fk", errs.ErrCertificateNotFound},
		{"crl_settings_signer_key_fk", errs.ErrKeyNotFound},
	} {
		t.Run(tc.constraint, func(t *testing.T) {
			err := signerError(&pgconn.PgError{Code: "23503", ConstraintName: tc.constraint})
			require.ErrorIs(t, err, tc.want)
		})
	}
}
