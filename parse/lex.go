package parse

import (
	"fmt"
	"strings"
)

type Expr struct {
	Op          string
	Left, Right *Expr
}

func Parse(s string) {
	l := newBPFLex(s)
	yyParse(l)
}

type bpfLex struct {
	tokens []string
}

var _ yyLexer = &bpfLex{}

func newBPFLex(f string) *bpfLex {
	return &bpfLex{
		tokens: strings.Split(f, " "),
	}
}

func (l *bpfLex) Lex(y *yySymType) int {

	var t = 0
	if len(l.tokens) > 0 {
		st := l.tokens[0]
		l.tokens = l.tokens[1:]

		switch st {
		case "+", "-", "*", "/", "=":
			t = EQ
			y.op = st
		case "tcp", "udp", "ip", "1":
			t = TCP
			y.key = st
		case "proto", "src", "dst":
			t = PROTO
			y.value = st
		default:
		}
	}
	return t
}

func (l *bpfLex) Error(s string) {
	fmt.Println("ERROR:", s)
}

func (l *bpfLex) setResult(e *Expr) {
	fmt.Println("setResult:", e)
}
