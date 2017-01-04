package main

import (
	"encoding/json"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

type testCaseVisitor struct {
	name  string
	cases map[string]*json.RawMessage
}

func (t *testCaseVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}
	if c, ok := node.(*ast.CallExpr); ok {
		if a := c.Args[1].(*ast.BasicLit); ok {
			data := json.RawMessage([]byte(constant.StringVal(
				constant.MakeFromLiteral(a.Value, a.Kind, 0),
			)))
			t.cases[t.name] = &data
		}
	}
	return t
}

func main() {
	var fset token.FileSet
	f, err := parser.ParseFile(&fset, os.Args[1], nil, 0)
	if err != nil {
		panic(err)
	}
	var v testCaseVisitor
	v.cases = make(map[string]*json.RawMessage)
	for _, decl := range f.Decls {
		if funcDecl, ok := decl.(*ast.FuncDecl); ok {
			if funcDecl.Recv == nil && strings.HasPrefix(funcDecl.Name.Name, "Test") {
				v.name = funcDecl.Name.Name
				ast.Walk(&v, funcDecl)
			}
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v.cases); err != nil {
		panic(err)
	}
}
