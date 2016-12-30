package main

import (
    "fmt"
    "go/token"
    "go/parser"
    "go/ast"
    "go/constant"
    "os"
    "strings"
)

type testCaseVisitor struct {
    name string
    cases map[string]string
}
func (t *testCaseVisitor) Visit(node ast.Node) ast.Visitor {
    if node == nil {
        return nil
    }
    if c, ok := node.(*ast.CallExpr); ok {
        if a := c.Args[1].(*ast.BasicLit); ok {
            fmt.Println(t.name, ":", constant.StringVal(constant.MakeFromLiteral(a.Value, a.Kind, 0)))
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
    var v testCaseVisitor;
    for _, decl := range f.Decls {
        if funcDecl, ok := decl.(*ast.FuncDecl); ok {
            if funcDecl.Recv == nil && strings.HasPrefix(funcDecl.Name.Name, "Test") {
                v.name = funcDecl.Name.Name
                ast.Walk(&v, funcDecl)
            }
        }
    }
}
