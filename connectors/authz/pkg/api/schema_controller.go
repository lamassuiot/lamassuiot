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

// GetSchemas returns all registered schemas — both entity (SQL-backed) schemas and
// HTTP route schemas — in a single response.
//
//	{
//	  "entity": { "<namespace>": [<SchemaDefinition>, ...], ... },
//	  "http":   { "<name>": <HTTPSchemaDefinition>, ... }
//	}
func (ctrl *SchemaController) GetSchemas(c *gin.Context) {
	grouped := make(map[string][]*engine.SchemaDefinition)
	for _, s := range ctrl.eng.GetSchemas().GetAll() {
		ns := s.ConfigSchema
		if ns == "" {
			ns = "default"
		}
		grouped[ns] = append(grouped[ns], s)
	}

	c.JSON(http.StatusOK, map[string]any{
		"entity": grouped,
		"http":   ctrl.eng.GetHTTPSchemas().GetAll(),
	})
}
