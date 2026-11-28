package dialect

import (
	"errors"
	"fmt"
	"testing"

	oracleerrors "github.com/oracle/go-oracledb/v26/oracle/errors"
	"gorm.io/gorm"
)

type fakeOracleError struct{ code string }

func (e fakeOracleError) Error() string     { return e.code + ": message" }
func (e fakeOracleError) ErrorCode() string { return e.code }

func TestTranslateMapsOracleErrorsLikePostgreSQL(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{
		{"ORA-00001", gorm.ErrDuplicatedKey},
		{"ORA-02291", gorm.ErrForeignKeyViolated},
		{"ORA-02292", gorm.ErrForeignKeyViolated},
		{"ORA-02290", gorm.ErrCheckConstraintViolated},
		{"ORA-00904", gorm.ErrInvalidField},
	} {
		// Drivers may wrap the Oracle error; the translator must still find it.
		original := fmt.Errorf("exec: %w", fakeOracleError{tc.code})
		got := Dialector{}.Translate(original)
		if !errors.Is(got, tc.want) {
			t.Errorf("%s: %v is not %v", tc.code, got, tc.want)
		}
		// Repositories tell constraints apart from the Oracle error.
		var sqlErr oracleerrors.SQLError
		if !errors.As(got, &sqlErr) || sqlErr.ErrorCode() != tc.code {
			t.Errorf("%s: translated error lost the Oracle error: %v", tc.code, got)
		}
	}
	for _, err := range []error{fakeOracleError{"ORA-01017"}, errors.New("not an Oracle error")} {
		if got := (Dialector{}).Translate(err); got != err {
			t.Errorf("untranslated error %v became %v", err, got)
		}
	}
}
