package controllers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestControllersPassRequestContextToDependencies guards against handing a
// *gin.Context to a dependency (r.svc.Method(ctx, ...)). gin.Context.Value only
// resolves string keys from its own map, so values stored in the request context
// by middlewares, such as the authz list filter, are lost and the storage layer
// runs unfiltered. Handlers must pass ctx.Request.Context() instead.
func TestControllersPassRequestContextToDependencies(t *testing.T) {
	// The backend controllers and the authz service controllers share the failure mode.
	var files []string
	for _, pattern := range []string{"*.go", "../../../connectors/authz/pkg/api/*.go"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		t.Fatal("no controller sources found")
	}

	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			var params *ast.FieldList
			var body *ast.BlockStmt
			switch fn := n.(type) {
			case *ast.FuncDecl:
				params, body = fn.Type.Params, fn.Body
			case *ast.FuncLit:
				params, body = fn.Type.Params, fn.Body
			default:
				return true
			}
			ginParams := ginContextParams(params)
			if len(ginParams) == 0 || body == nil {
				return true
			}
			ast.Inspect(body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				arg, ok := call.Args[0].(*ast.Ident)
				if !ok || !ginParams[arg.Name] {
					return true
				}
				// Only calls on a field of the receiver (r.svc.Method) reach other layers;
				// local helpers and ctx's own methods legitimately take the gin context.
				method, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if _, onField := method.X.(*ast.SelectorExpr); onField {
					t.Errorf("%s: pass %s.Request.Context() instead of the *gin.Context to %s",
						fset.Position(call.Pos()), arg.Name, exprString(call.Fun))
				}
				return true
			})
			return true
		})
	}
}

func ginContextParams(params *ast.FieldList) map[string]bool {
	names := map[string]bool{}
	if params == nil {
		return names
	}
	for _, field := range params.List {
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Context" {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "gin" {
			continue
		}
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	return names
}

func exprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	default:
		return "<expr>"
	}
}
