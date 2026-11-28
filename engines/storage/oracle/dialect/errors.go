package dialect

import (
	"errors"
	"fmt"

	oracleerrors "github.com/oracle/go-oracledb/v26/oracle/errors"
	"gorm.io/gorm"
)

// oracleErrors maps Oracle errors to the GORM errors that the PostgreSQL
// dialect reports for the equivalent SQLSTATE codes.
var oracleErrors = map[string]error{
	"ORA-00001": gorm.ErrDuplicatedKey,           // unique constraint violated (23505)
	"ORA-02291": gorm.ErrForeignKeyViolated,      // parent key not found (23503)
	"ORA-02292": gorm.ErrForeignKeyViolated,      // child record found (23503)
	"ORA-02290": gorm.ErrCheckConstraintViolated, // check constraint violated (23514)
	"ORA-00904": gorm.ErrInvalidField,            // invalid identifier (42703)
}

var _ gorm.ErrorTranslator = Dialector{}

// Translate implements gorm.ErrorTranslator, used when gorm.Config enables
// TranslateError. The result wraps both the GORM error and the original Oracle
// error, so callers can test for either; repositories still inspect the
// Oracle error to tell constraints apart.
func (Dialector) Translate(err error) error {
	var sqlErr oracleerrors.SQLError
	if !errors.As(err, &sqlErr) {
		return err
	}
	translated, ok := oracleErrors[sqlErr.ErrorCode()]
	if !ok {
		return err
	}
	return fmt.Errorf("%w: %w", translated, err)
}
