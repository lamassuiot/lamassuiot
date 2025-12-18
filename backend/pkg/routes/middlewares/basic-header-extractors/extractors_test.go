package headerextractors

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3"
)

func TestUpdateContextWithRequest(t *testing.T) {
	// Create a gin.Context with a proper Request
	ctx := &gin.Context{
		Request: &http.Request{},
	}
	ctx.Request = ctx.Request.WithContext(context.Background())

	headers := http.Header{}
	headers.Set("x-lms-source", "test-source")
	headers.Set("x-ignored", "ignored")

	// Verify that the source is correctly set in gin.Context (backward compatibility)
	source := ctx.Value(core.LamassuContextKeySource)
	if !strings.HasPrefix(source.(string), "test-source") {
		t.Errorf("UpdateContextWithRequest did not set the correct source in gin.Context. Expected: %s, Got: %v", "test-source", source)
	}

	// Verify that the source is correctly set in request.Context (for services)
	sourceFromReqCtx := ctx.Request.Context().Value(core.LamassuContextKeySource)
	if !strings.HasPrefix(sourceFromReqCtx.(string), "test-source") {
		t.Errorf("UpdateContextWithRequest did not set the correct source in request.Context. Expected: %s, Got: %v", "test-source", sourceFromReqCtx)
	}

	// Verify that the ignored header is not set in the context
	ignored := ctx.Value("x-ignored")
	if ignored != nil {
		t.Errorf("UpdateContextWithRequest should not have set the ignored header in the context. Got: %v", ignored)
	}
}
