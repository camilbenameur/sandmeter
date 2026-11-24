//go:build integration && linux

package kernelfacts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Most of this package only runs as root, on a runner. A fact recorded
// under a misspelt identifier, or by a test that never declared it, would
// stop that test there, and show nowhere else. So this test reads the
// source of the package instead of running it: every identifier written in
// a test file is checked against the catalogue and against what the tests
// of that file declare.

// recorderMethods are the methods of recorder whose first argument is the
// identifier of a fact.
var recorderMethods = []string{"record", "yes", "no", "skip", "judge"}

// stringLiteral returns the value of an expression that is a string literal.
func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// factUses is what one test file says about facts.
type factUses struct {
	declared  []string // literal arguments of declare
	recorded  []string // literal first arguments of the recorder's methods
	mentioned []string // every other string literal that is an identifier of the catalogue
	opaque    int      // arguments of declare that are not literals
}

// factUsesIn parses one file of the package.
func factUsesIn(path string) (factUses, error) {
	var u factUses
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return u, err
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			switch fn := n.Fun.(type) {
			case *ast.Ident:
				if fn.Name != "declare" || len(n.Args) == 0 {
					break
				}
				for _, arg := range n.Args[1:] {
					if id, ok := stringLiteral(arg); ok {
						u.declared = append(u.declared, id)
					} else {
						u.opaque++
					}
				}
				return false
			case *ast.SelectorExpr:
				if !slices.Contains(recorderMethods, fn.Sel.Name) || len(n.Args) == 0 {
					break
				}
				if id, ok := stringLiteral(n.Args[0]); ok {
					u.recorded = append(u.recorded, id)
					// The other arguments may still name a fact.
					for _, arg := range n.Args[1:] {
						ast.Inspect(arg, func(n ast.Node) bool {
							if e, ok := n.(ast.Expr); ok {
								if id, ok := stringLiteral(e); ok {
									if _, known := catalogued(id); known {
										u.mentioned = append(u.mentioned, id)
									}
								}
							}
							return true
						})
					}
					return false
				}
			}
		case *ast.BasicLit:
			if id, ok := stringLiteral(n); ok {
				if _, known := catalogued(id); known {
					u.mentioned = append(u.mentioned, id)
				}
			}
		}
		return true
	})
	return u, nil
}

func TestSelfFactsInSource(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	declaredIn := map[string]string{} // fact, and the file whose test declares it
	files := 0
	for _, e := range entries {
		name := e.Name()
		// The catalogue is the list itself, not a use of it.
		if !strings.HasSuffix(name, "_test.go") || name == "catalogue_test.go" {
			continue
		}
		files++
		u, err := factUsesIn(name)
		if err != nil {
			t.Errorf("%s does not parse: %v", name, err)
			continue
		}
		if u.opaque > 0 {
			t.Errorf("%s calls declare with %d arguments that are not string literals: this test cannot see which facts they are", name, u.opaque)
		}
		for _, id := range u.declared {
			if _, ok := catalogued(id); !ok {
				t.Errorf("%s declares %q, which is not in the catalogue", name, id)
			}
			if other, dup := declaredIn[id]; dup {
				t.Errorf("fact %s is declared twice, in %s and in %s: only one test can record it", id, other, name)
			}
			declaredIn[id] = name
		}
		for _, id := range u.recorded {
			if _, ok := catalogued(id); !ok {
				t.Errorf("%s records %q, which is not in the catalogue", name, id)
			} else if !slices.Contains(u.declared, id) {
				t.Errorf("%s records %s, which no test of that file declares", name, id)
			}
		}
		for _, id := range u.mentioned {
			if !slices.Contains(u.declared, id) {
				t.Errorf("%s names the fact %s, which no test of that file declares", name, id)
			}
		}
	}
	if files == 0 {
		t.Fatalf("no test file found in the working directory: the tests of a package run in its directory")
	}
	for _, d := range catalogue {
		if _, ok := declaredIn[d.id]; !ok {
			t.Errorf("fact %s of the catalogue is declared by no test", d.id)
		}
	}
}

// The reader of the source, on a source written for it.
func TestSelfFactUses(t *testing.T) {
	known := catalogue[0].id
	src := `package p

func TestA(t *testing.T) {
	r := declare(t, "` + known + `", "not-in-the-catalogue", someVariable)
	r.judge("` + known + `", true, "detail that names %s", "` + known + `")
	r.no("misspelt", "detail")
	helper(r, "` + known + `")
	t.Log("judge", "skip")
}
`
	path := t.TempDir() + "/sample_test.go"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	u, err := factUsesIn(path)
	if err != nil {
		t.Fatal(err)
	}
	want := factUses{
		declared:  []string{known, "not-in-the-catalogue"},
		recorded:  []string{known, "misspelt"},
		mentioned: []string{known, known},
		opaque:    1,
	}
	if !slices.Equal(u.declared, want.declared) || !slices.Equal(u.recorded, want.recorded) ||
		!slices.Equal(u.mentioned, want.mentioned) || u.opaque != want.opaque {
		t.Errorf("factUsesIn read %+v, want %+v", u, want)
	}
}
