package main

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
)

const src = `package p
const maxLen = 1e3
func f(s string) string { return s[:maxLen] }
func g(s string) string { return s[complex(1,0):3] }
`

func main() {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		panic(err)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	conf := types.Config{Importer: importer.Default()}
	if _, err := conf.Check("p", fset, []*ast.File{file}, info); err != nil {
		panic(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if se, ok := n.(*ast.SliceExpr); ok {
			for _, b := range []ast.Expr{se.Low, se.High} {
				if b == nil {
					continue
				}
				tv := info.Types[b]
				fmt.Printf("bound=%s resolved-type=%s value=%v\n", types.ExprString(b), tv.Type, tv.Value)
			}
		}
		return true
	})
}
