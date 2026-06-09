package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/engine"
)

type SchemaController struct {
	eng *engine.Engine
}

func NewSchemaController(eng *engine.Engine) *SchemaController {
	return &SchemaController{
		eng: eng,
	}
}

// GetSchemas godoc
// @Summary Get all entity schemas
// @Description Returns all registered entity schemas grouped by authorization namespace
// @Tags schema
// @Produce json
// @Success 200 {object} map[string][]engine.SchemaDefinition
// @Router /api/v1/schemas [get]
func (ctrl *SchemaController) GetSchemas(c *gin.Context) {
	schemas := ctrl.eng.GetSchemas().GetAll()

	// Group schemas by config schema (authorization namespace)
	grouped := make(map[string][]*engine.SchemaDefinition)
	for _, schema := range schemas {
		configSchema := schema.ConfigSchema
		if configSchema == "" {
			configSchema = "default"
		}
		grouped[configSchema] = append(grouped[configSchema], schema)
	}

	c.JSON(http.StatusOK, grouped)
}
