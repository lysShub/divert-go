package parse

import (
	"fmt"
	"strings"
)

type Expr interface {
	String() string
}

type BinaryExpr struct {
	op          string
	left, right Expr
}

func (e *BinaryExpr) Left() Expr {
	return e.left
}

func (e *BinaryExpr) Right() Expr {
	return e.right
}

func (e *BinaryExpr) Op() string {
	return e.op
}

func (e *BinaryExpr) String() string {
	return fmt.Sprintf("%s %s %s", e.left, e.op, e.right)
}

type StrLiteral struct {
	Str string
}

func (e *StrLiteral) String() string {
	return e.Str
}

type IntLiteral struct {
	Int float64
}

func (e *IntLiteral) String() string {
	return fmt.Sprintf("%f", e.Int)
}
