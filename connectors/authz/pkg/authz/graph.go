package authz

import (
	"fmt"

	"github.com/lamassuiot/authz/pkg/models"
)

// GraphNode represents a node in the authorization graph
type GraphNode struct {
	EntityType string
	Relations  map[string]*GraphEdge // via -> edge
}

// GraphEdge represents a directed edge in the authorization graph
type GraphEdge struct {
	From               string   // source entity type
	To                 string   // target entity type
	Via                string   // relation name (FK in schema)
	Actions            []string // allowed actions through this edge
	ForeignKey         string   // FK column name in target table
	TableName          string   // target table name
	QualifiedTableName string   // schema-qualified table name (schema.table)
	PrimaryKey         string   // target primary key
}

// AuthorizationGraph represents the complete entity relationship graph
type AuthorizationGraph struct {
	nodes map[string]*GraphNode
}

// NewAuthorizationGraph creates a new authorization graph
func NewAuthorizationGraph() *AuthorizationGraph {
	return &AuthorizationGraph{
		nodes: make(map[string]*GraphNode),
	}
}

// BuildFromPoliciesAndSchemas constructs the graph from policy and schema definitions
func (g *AuthorizationGraph) BuildFromPoliciesAndSchemas(policies *PolicyRegistry, schemas *SchemaRegistry) error {
	// Create nodes for all entity types from schemas (use qualified entity types)
	for qualifiedType, schema := range schemas.GetAll() {
		if _, exists := g.nodes[qualifiedType]; !exists {
			g.nodes[qualifiedType] = &GraphNode{
				EntityType: qualifiedType,
				Relations:  make(map[string]*GraphEdge),
			}
		}
		// Also create node with simple name for backward compatibility
		if _, exists := g.nodes[schema.EntityType]; !exists {
			g.nodes[schema.EntityType] = &GraphNode{
				EntityType: schema.EntityType,
				Relations:  make(map[string]*GraphEdge),
			}
		}
	}

	// Add user node (virtual node for user ownership)
	g.nodes["user"] = &GraphNode{
		EntityType: "user",
		Relations:  make(map[string]*GraphEdge),
	}

	// Build edges from policies/rules
	for _, policy := range policies.GetAll() {
		for _, rule := range policy.Rules {
			matchedSchemas := 0
			for _, schema := range schemas.GetAll() {
				if !ruleMatchesSchema(rule, schema) {
					continue
				}
				matchedSchemas++

				concreteRule := concretizeRuleForSchema(rule, schema)
				if err := g.addRuleEdges(concreteRule.QualifiedEntityType(), concreteRule.Namespace, concreteRule, schemas); err != nil {
					return err
				}
			}

			if matchedSchemas == 0 && (rule.SchemaName == "*" || rule.EntityType == "*") {
				return fmt.Errorf("wildcard rule matched no schemas: namespace=%s schemaName=%s entityType=%s",
					rule.Namespace,
					rule.SchemaName,
					rule.EntityType,
				)
			}
		}
	}

	// Add direct user ownership edges from schemas
	for _, schema := range schemas.GetAll() {
		for _, relConfig := range schema.Relations {
			if relConfig.TargetEntity == "user" {
				// Edge from entity to user
				edge := &GraphEdge{
					From:               schema.QualifiedEntityType(),
					To:                 "user",
					Via:                relConfig.ForeignKey,
					ForeignKey:         relConfig.ForeignKey,
					TableName:          schema.TableName,
					QualifiedTableName: schema.QualifiedTableName(),
					PrimaryKey:         schema.PrimaryKeys[0],
				}
				qualifiedType := schema.QualifiedEntityType()
				if g.nodes[qualifiedType] != nil {
					g.nodes[qualifiedType].Relations[relConfig.ForeignKey] = edge
				}
				// Also add to simple name node for backward compatibility
				if g.nodes[schema.EntityType] != nil {
					g.nodes[schema.EntityType].Relations[relConfig.ForeignKey] = edge
				}
			}
		}
	}

	return nil
}

// addRuleEdges adds edges from a policy's relations
func (g *AuthorizationGraph) addRuleEdges(entityType string, namespace string, rule *models.Rule, schemas *SchemaRegistry) error {
	return g.addRelationEdges(entityType, namespace, rule.Relations, schemas)
}

// addRelationEdges recursively adds edges from relation policies
func (g *AuthorizationGraph) addRelationEdges(fromEntity string, fromNamespace string, relations []models.RelationRule, schemas *SchemaRegistry) error {
	for _, rel := range relations {
		targetEntityType := rel.QualifiedTo()

		// Get target schema to find table details - must match namespace
		// Relations always use the parent rule's namespace
		var targetSchema *SchemaDefinition
		for _, schema := range schemas.GetAll() {
			if schema.ConfigSchema == fromNamespace && schema.QualifiedEntityType() == targetEntityType {
				targetSchema = schema
				break
			}
		}
		if targetSchema == nil {
			return fmt.Errorf("schema not found for namespace=%s, entityType=%s", fromNamespace, targetEntityType)
		}

		// Via is the foreign key column name - use it directly

		// Create edge from source to target
		edge := &GraphEdge{
			From:               fromEntity,
			To:                 targetEntityType,
			Via:                rel.Via,
			Actions:            rel.Actions,
			ForeignKey:         rel.Via, // Via IS the foreign key column
			TableName:          targetSchema.TableName,
			QualifiedTableName: targetSchema.QualifiedTableName(),
			PrimaryKey:         targetSchema.PrimaryKeys[0],
		}

		if g.nodes[fromEntity] != nil {
			// Check if edge already exists - merge actions if so
			if existingEdge, exists := g.nodes[fromEntity].Relations[rel.Via]; exists {
				// Merge actions - add new actions that don't already exist
				actionSet := make(map[string]bool)
				for _, action := range existingEdge.Actions {
					actionSet[action] = true
				}
				for _, action := range rel.Actions {
					if !actionSet[action] {
						existingEdge.Actions = append(existingEdge.Actions, action)
					}
				}
			} else {
				g.nodes[fromEntity].Relations[rel.Via] = edge
			}
		}

		// Recursively add nested relations (using same namespace as parent)
		if len(rel.Relations) > 0 {
			if err := g.addRelationEdges(targetEntityType, fromNamespace, rel.Relations, schemas); err != nil {
				return err
			}
		}
	}
	return nil
}

// FindPathsToUser finds all paths from an entity type to user ownership
// Returns list of paths, where each path is a list of edges
func (g *AuthorizationGraph) FindPathsToUser(fromEntity string, action string, maxDepth int) [][]*GraphEdge {
	var paths [][]*GraphEdge
	var currentPath []*GraphEdge
	visited := make(map[string]bool)

	g.dfsToUser(fromEntity, action, currentPath, visited, &paths, 0, maxDepth)
	return paths
}

// dfsToUser performs depth-first search to find paths to user
func (g *AuthorizationGraph) dfsToUser(current string, action string, currentPath []*GraphEdge, visited map[string]bool, paths *[][]*GraphEdge, depth int, maxDepth int) {
	if depth > maxDepth {
		return
	}

	if visited[current] {
		return
	}

	// Mark as visited
	visited[current] = true
	defer func() { visited[current] = false }()

	node := g.nodes[current]
	if node == nil {
		return
	}

	// Check each edge from this node
	for _, edge := range node.Relations {
		// Check if this edge supports the action
		if edge.To == "user" || g.edgeSupportsAction(edge, action) {
			// Add edge to current path
			newPath := append(currentPath, edge)

			if edge.To == "user" {
				// Found a path to user
				pathCopy := make([]*GraphEdge, len(newPath))
				copy(pathCopy, newPath)
				*paths = append(*paths, pathCopy)
			} else {
				// Continue searching
				g.dfsToUser(edge.To, action, newPath, visited, paths, depth+1, maxDepth)
			}
		}
	}
}

// edgeSupportsAction checks if an edge supports a specific action
func (g *AuthorizationGraph) edgeSupportsAction(edge *GraphEdge, action string) bool {
	for _, a := range edge.Actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

// FindPathsBetween finds all paths from source entity to target entity
func (g *AuthorizationGraph) FindPathsBetween(from string, to string, action string, maxDepth int) [][]*GraphEdge {
	var paths [][]*GraphEdge
	var currentPath []*GraphEdge
	visited := make(map[string]bool)

	g.dfsBetween(from, to, action, currentPath, visited, &paths, 0, maxDepth)
	return paths
}

// dfsBetween performs depth-first search between two entity types
func (g *AuthorizationGraph) dfsBetween(current string, target string, action string, currentPath []*GraphEdge, visited map[string]bool, paths *[][]*GraphEdge, depth int, maxDepth int) {
	if depth > maxDepth {
		return
	}

	if current == target {
		// Found a path - verify the last edge supports the action
		if len(currentPath) > 0 {
			lastEdge := currentPath[len(currentPath)-1]
			if g.edgeSupportsAction(lastEdge, action) {
				pathCopy := make([]*GraphEdge, len(currentPath))
				copy(pathCopy, currentPath)
				*paths = append(*paths, pathCopy)
			}
		}
		return
	}

	if visited[current] {
		return
	}

	visited[current] = true
	defer func() { visited[current] = false }()

	node := g.nodes[current]
	if node == nil {
		return
	}

	for _, edge := range node.Relations {
		// Follow all edges to explore paths
		// Action check will be done only on the final edge when we reach the target
		newPath := append(currentPath, edge)
		g.dfsBetween(edge.To, target, action, newPath, visited, paths, depth+1, maxDepth)
	}
}

// GetNode returns a node by entity type
func (g *AuthorizationGraph) GetNode(entityType string) *GraphNode {
	return g.nodes[entityType]
}

// GetAllNodes returns all nodes in the graph
func (g *AuthorizationGraph) GetAllNodes() map[string]*GraphNode {
	return g.nodes
}
