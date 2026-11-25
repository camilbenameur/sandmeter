package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMainDispatchesFirst reads the source of this command: the function
// main exists once, and its first statement is the call that hands control
// to a hidden entry point. Whatever main becomes, nothing in it may run
// before that call.
func TestMainDispatchesFirst(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "main" || fn.Recv != nil {
				continue
			}
			found++
			if len(fn.Body.List) == 0 {
				t.Fatalf("%s: main is empty", name)
			}
			first := ""
			if stmt, ok := fn.Body.List[0].(*ast.ExprStmt); ok {
				if call, ok := stmt.X.(*ast.CallExpr); ok && len(call.Args) == 0 {
					if id, ok := call.Fun.(*ast.Ident); ok {
						first = id.Name
					}
				}
			}
			if first != "dispatchHidden" {
				t.Errorf("%s: the first statement of main must be dispatchHidden()", name)
			}
		}
	}
	if found != 1 {
		t.Fatalf("found %d main functions in %v, want one", found, files)
	}
}

// TestTheRootServiceDispatchesTheHandshakeTableOnly reads the source of this
// command once more. The root service answers to the entry points that begin
// with the handshake and to no other: the dispatch that also answers to the
// init of the first backend, which has none, is for the binaries that still
// run that backend in their own process, and this is not one of them.
func TestTheRootServiceDispatchesTheHandshakeTableOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "DispatchLegacy") {
			t.Errorf("%s uses the dispatch that answers to an entry point without a handshake", name)
		}
		calls += strings.Count(string(src), "hidden.Dispatch(os.Args)")
	}
	if calls != 1 {
		t.Errorf("found %d calls of hidden.Dispatch(os.Args) in %v, want the one of dispatchHidden", calls, files)
	}
}
