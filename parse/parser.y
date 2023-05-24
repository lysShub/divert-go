%{
    package parse

    // import "strings"



    // goyacc -l -o parser.go parser.y
%}

%union{
    result  *Expr
    
    key,op,value     string
}



%type <result>  expr
%type <key>     key 
%type <op>      op
%type <value>   value


%token <op> 
    EQ      "="    
    NE      "!="


%token <key>
    PROTO   "proto"


%token <value>
    TCP     "tcp"
    UDP     "udp"


%start Start

%%

Start: expr
    {
        yylex.(*bpfLex).setResult($1)
    }
;

expr:
    expr op expr
    {
       $$ = &Expr{ Op:$2, Left:$1, Right:$3 } 
    }
    | key op value
    {
        $$ = &Expr{}
    }
    | key op key
    {
        $$ = &Expr{}
    }
;


key: 
    PROTO
    {
        $$ = $1
    }
;

op:
    EQ
    {
        $$ = $1
    }
    | NE
    {
        $$ = $1
    }
;

value:
    TCP
    {
        $$ = $1
    }
    | UDP
    {
        $$ = $1
    }
;