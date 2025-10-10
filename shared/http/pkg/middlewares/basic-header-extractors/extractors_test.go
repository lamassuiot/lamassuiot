package headerextractors

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3"
)

func TestUpdateContextWithRequest(t *testing.T) {
	ctx := gin.Context{}
	headers := http.Header{}
	headers.Set("x-request-id", "12345")
	headers.Set("x-lms-source", "test-source")
	headers.Set("x-ignored", "ignored")

	updateContextWithRequestWithRequestID(&ctx, headers)
	updateContextWithRequestWithSource(&ctx, headers)

	// Verify that the request ID is correctly set in the context
	reqID := ctx.Value(core.LamassuContextKeyRequestID)
	if reqID != "12345" {
		t.Errorf("UpdateContextWithRequest did not set the correct request ID in the context. Expected: %s, Got: %v", "12345", reqID)
	}

	// Verify that the source is correctly set in the context
	source := ctx.Value(core.LamassuContextKeySource)
	if !strings.HasPrefix(source.(string), "test-source") {
		t.Errorf("UpdateContextWithRequest did not set the correct source in the context. Expected: %s, Got: %v", "test-source", source)
	}

	// Verify that the source is correctly set in the context
	ignored := ctx.Value("x-ignored")
	if ignored != nil {
		t.Errorf("UpdateContextWithRequest should not have set the ignored header in the context. Got: %v", ignored)
	}
}
