package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
)

func main() {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", `package sample
func f(s string) string { return s[1.0:complex(3,0)] }
`, 0)
	if err != nil { panic(err) }
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	var conf types.Config
	if _, err := conf.Check("sample", fset, []*ast.File{file}, info); err != nil { panic(err) }
	ast.Inspect(file,func(n ast.Node)bool {
		if slice,ok := n.(*ast.SliceExpr); ok {
			for _,bound := range []ast.Expr{slice.Low,slice.High} {
				value := info.Types[bound]
				fmt.Printf("bound=%T resolved-type=%s constant=%s\n",bound,value.Type,value.Value)
			}
		}
		return true
	})
}
