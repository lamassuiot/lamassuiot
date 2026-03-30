package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/authz"
)

type SchemaController struct {
	engine *authz.Engine
}

func NewSchemaController(engine *authz.Engine) *SchemaController {
	return &SchemaController{
		engine: engine,
	}
}

// GetSchemas godoc
// @Summary Get all entity schemas
// @Description Returns all registered entity schemas grouped by authorization namespace
// @Tags schema
// @Produce json
// @Success 200 {object} map[string][]authz.SchemaDefinition
// @Router /api/v1/schemas [get]
func (ctrl *SchemaController) GetSchemas(c *gin.Context) {
	schemas := ctrl.engine.GetSchemas().GetAll()

	// Group schemas by config schema (authorization namespace)
	grouped := make(map[string][]*authz.SchemaDefinition)
	for _, schema := range schemas {
		configSchema := schema.ConfigSchema
		if configSchema == "" {
			configSchema = "default"
		}
		grouped[configSchema] = append(grouped[configSchema], schema)
	}

	c.JSON(http.StatusOK, grouped)
}
