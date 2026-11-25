package revocation

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestPackageImportsNoIO keeps the package a leaf without I/O: it may import the standard library and the OCSP codec,
// but no package of this repository and nothing that reaches the network or the file system.
func TestPackageImportsNoIO(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("could not list package files: %s", err)
	}

	files := 0
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("could not parse %s: %s", name, err)
		}
		files++
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: malformed import %s", name, imp.Path.Value)
			}
			if reason := forbiddenImport(path); reason != "" {
				t.Errorf("%s imports %q: %s", name, path, reason)
			}
		}
	}
	if files == 0 {
		t.Fatalf("no source file found")
	}
}

func forbiddenImport(path string) string {
	first, _, _ := strings.Cut(path, "/")
	switch {
	case path == "golang.org/x/crypto/ocsp":
		return ""
	case strings.HasPrefix(path, "github.com/lamassuiot/"):
		return "the package must not depend on this repository"
	case strings.Contains(first, "."):
		return "only the standard library and golang.org/x/crypto/ocsp are allowed"
	case first == "net" || first == "os":
		return "the package must not perform I/O"
	}
	return ""
}
