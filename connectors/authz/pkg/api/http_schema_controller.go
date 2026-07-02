package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/engine"
)

// HTTPSchemaController exposes HTTP schema introspection endpoints.
type HTTPSchemaController struct {
	eng *engine.Engine
}

// NewHTTPSchemaController creates an HTTPSchemaController.
func NewHTTPSchemaController(eng *engine.Engine) *HTTPSchemaController {
	return &HTTPSchemaController{eng: eng}
}

// GetHTTPSchemas handles GET /v1/http_schemas.
// Returns all registered HTTP schema definitions.
func (ctrl *HTTPSchemaController) GetHTTPSchemas(c *gin.Context) {
	c.JSON(http.StatusOK, ctrl.eng.GetHTTPSchemas().GetAll())
}
