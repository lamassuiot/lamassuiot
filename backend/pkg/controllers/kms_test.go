package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/stretchr/testify/assert"
)

// Middlewares such as the event publisher wrap the errors they get from the service, which must not
// turn a known error into a server error.
func TestKMSHandleErrorMatchesWrappedErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	routes := NewKMSHttpRoutes(nil)

	for _, test := range []struct {
		err    error
		status int
	}{
		{errs.ErrKeyNotFound, http.StatusNotFound},
		{fmt.Errorf("mw error: could not get Key k: %w", errs.ErrKeyNotFound), http.StatusNotFound},
		{fmt.Errorf("mw error: could not get Key k: %w", errs.ErrKeyEngineRequired), http.StatusBadRequest},
		{fmt.Errorf("mw error: %w", errs.ErrKeyBindingsReadOnly), http.StatusBadRequest},
		{fmt.Errorf("mw error: %w", errs.ErrValidateBadRequest), http.StatusBadRequest},
		{errors.New("storage unavailable"), http.StatusInternalServerError},
	} {
		response := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(response)

		routes.handleError(ctx, test.err)

		assert.Equal(t, test.status, response.Code, test.err.Error())
	}
}
