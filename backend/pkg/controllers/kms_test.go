package controllers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/stretchr/testify/assert"
)

// The KMS service wraps the errors it adds context to, and the status of the response follows the cause.
func TestKMSHandleErrorMapsWrappedErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for name, tc := range map[string]struct {
		err    error
		status int
	}{
		"key not found":                 {errs.ErrKeyNotFound, http.StatusNotFound},
		"wrapped key not found":         {fmt.Errorf("failed to delete key: %w", errs.ErrKeyNotFound), http.StatusNotFound},
		"key in use":                    {errs.ErrKeyInUse, http.StatusConflict},
		"wrapped key in use":            {fmt.Errorf("failed to delete key: %w", errs.ErrKeyInUse), http.StatusConflict},
		"engine required":               {errs.ErrKeyEngineRequired, http.StatusBadRequest},
		"wrapped validation error":      {fmt.Errorf("invalid: %w", errs.ErrValidateBadRequest), http.StatusBadRequest},
		"alias colliding with a key_id": {errs.ErrKeyAliasCollidesWithKeyID, http.StatusBadRequest},
		"unknown error":                 {fmt.Errorf("boom"), http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)

			NewKMSHttpRoutes(nil).handleError(ctx, tc.err)

			assert.Equal(t, tc.status, recorder.Code)
		})
	}
}
