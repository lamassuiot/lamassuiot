package validator

import (
	"runtime"

	"github.com/sirupsen/logrus"
)

func logInputValidationError(err error, logger *logrus.Entry) {
	//Get caller function name
	pc := make([]uintptr, 10) // at least 1 entry needed
	runtime.Callers(2, pc)
	funcName := runtime.FuncForPC(pc[0])

	logger.Errorf("Validation error in %s: %s", funcName.Name(), err.Error())
}
