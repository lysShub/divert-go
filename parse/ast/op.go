package ast

type Op int

func (o Op) Priority() int {
	return int(priority[o])
}

const (
	_ Op = iota
	EQ
	EQ2
	NE
	GT
	GE
	LT
	LE
)

var priority = [...]Op{
	GE: 4,
	GT: 4,
	LE: 4,
	LT: 4,
	NE: 5,
	EQ: 5,
}
