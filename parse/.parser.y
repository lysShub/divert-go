%{
    package parse

    // import "strings"



    // goyacc -l -o parser.go parser.y
%}

%union{
    expr    Expr
    item    any
}

%type <expr> 
    Expr       "expr"
    BinaryExpr "binary expr"
    StrLiteral "string literal"
;

/* op */
%type <item>
    Op    "operator token"
    CmpOP "compareable operator"
    SortOP "sortable operator"
    LogicOP "logic operator"
;

/* field */
%type <item>
    IPField    "ip field"
    IPAnyField "ip any field"
    ICMPField  "icmp field"
    ICMPAnyField "icmp any field"
    ProtoField "proto field"
    ProtoAnyField "proto any field"
    FilterField "filter field"
    LayerField  "layer field"
    EventField  "event field"
    BoundField  "bound field"
    IfField     "interface field"
    RandomField "random field"
    OffsetField "offset field"
;

/* value  */
%type <item>
    Value "value token"

%token <item>
    /* op token */
    EQ      "="
    EQ2     "=="    
    NE      "!="
    GT      ">"
    GE      ">="
    LT      "<"
    LE      "<="
    AND     "and"
    AND2    "&&"
    OR      "or"
    OR2     "||"
    /* field token */
    timestamp           "timestamp"
    event               "event"
    ifidx               "ifidx"
    subifidx            "subifidx"
    loopback            "loopback"
    impostor            "impostor"
    fragment            "fragment"
    endpointid          "endpointid"
    parentendpointid    "parentendpointid"
    processid           "processid"
    random8             "random8"
    random16            "random16"
    random32            "random32"
    layer               "layer"
    priority            "priority"
    packet_i            "packet[i]"
    packet16_i          "packet16[i]"
    packet32_i          "packet32[i]"
    length              "length"
    protocol            "protocol"
    localAddr           "localAddr"
    localPort           "localPort"
    remoteAddr          "remoteAddr"
    remotePort          "remotePort"
    tcp_PayloadLength   "tcp.PayloadLength"
    tcp_Payload_i       "tcp.Payload[i]"
    tcp_Payload16_i     "tcp.Payload16[i]"
    tcp_Payload32_i     "tcp.Payload32[i]"
    udp_PayloadLength   "udp.PayloadLength"
    udp_Payload_i       "udp.Payload[i]"
    udp_Payload16_i     "udp.Payload16[i]"
    udp_Payload32_i     "udp.Payload32[i]"
    /* value token */
    zero            "0"
    TRUE            "true"
    FALSE           "false"
    TCP_NAME        "tcp name"
    UDP_NAME        "udp name"
    ICMP_NAME       "icmp name"
    ICMP6_NAME      "icmp6 name"
    PACKET          "packet"
    ESTABLISHED     "established"
    DELETED         "deleted"
    BIND            "bind"
    CONECT          "connect"
    ACCEPT          "accept"
    LISTEN          "listen"
    OPEN            "open"
    CLOSE           "close"
    NETWORK         "network"
    NETWORK_FORWARD "network forward"
    FLOW            "flow"
    SOCKET          "socket"
    REFLECT         "reflect"

    outbound        "outbound"
    inbound         "inbound"
    ip              "ip"
    ip6             "ip6"
    icmp            "icmp"
    icmp6           "icmp6"
    tcp             "tcp"
    udp             "udp"
    ip_any          "ip.*"
    ip6_any         "ip6.*"
    icmp_any        "icmp.*"
    icmp6_any       "icmp6.*"
    tcp_any         "tcp.*"
    udp_any         "udp.*"
;





%start Start

%%

Start: Expr
    {
        yylex.(*bpfLex).setResult($1)
    }
;

Expr:
    BinaryExpr
    | StrLiteral
    {
        $$ = $1
    }
;

BinaryExpr:
    BinaryExpr LogicOP BinaryExpr
    {
        $$ = &BinaryExpr{left:$1, op:$2, right:$3}
    }
    | IPField
    {
        $$ = &IPVersion{}
    }
;





Op:
    CmpOP
    | SortOP
    | LogicOP
    {
        $$ = $1
    }
;

CmpOP:
    EQ
    {
        $$ = ast.EQ
    }
    | EQ2
    {
        $$ = ast.EQ2
    }
    | NE
    {
        $$ = ast.NE
    }
;

SortOP:
    GT
    {
        $$ = ast.GT
    }
    | GE
    {
        $$ = ast.GE
    }
    | LT
    {
        $$ = ast.LT
    }
    | LE
    {
        $$ = ast.LE
    }
;

LogicOP:
    AND
    {
        $$ = ast.AND
    }
    | AND2
    {
        $$ = ast.AND2
    }
    | OR
    {
        $$ = ast.OR
    }
    | OR2
    {
        $$ = ast.OR2
    }
;

IPField:
    ip
    {
        $$ = $1
    }
    | ip6
    {
        $$ = $1
    }
;

IPAnyField:
    ip_any
    {
        $$ = $1
    }
    | ip6_any
    {
        $$ = $1
    }
;

ICMPField:
    icmp
    {
        $$ = $1
    }
    | icmp6
    {
        $$ = $1
    }
;

ICMPAnyField:
    icmp_any
    {
        $$ = $1
    }
    | icmp6_any
    {
        $$ = $1
    }
;

ProtoField:
    tcp
    {
        $$ = $1
    }
    | udp
    {
        $$ = $1
    }
;

ProtoAnyField:
    tcp_any
    {
        $$ = $1
    }
    | udp_any
    {
        $$ = $1
    }
;


FilterField:
    protocol
    {
        $$ = $1
    }
    | localAddr
    {
        $$ = $1
    }
    | localPort
    {
        $$ = $1
    }
    | remoteAddr
    {
        $$ = $1
    }
    | remotePort
    {
        $$ = $1
    }
;

LayerField:
    layer
    {
        $$ = $1
    }
;

EventField:
    event
    {
        $$ = $1
    }
;

BoundField:
    outbound
    {
        $$ = $1
    }
    | inbound
    {
        $$ = $1
    }
;

IfField:
    ifidx
    {
        $$ = $1
    }
    | subifidx
    {
        $$ = $1
    }
    | loopback
    {
        $$ = $1
    }
    | impostor
    {
        $$ = $1
    }
    | fragment
    {
        $$ = $1
    }
    | endpointid
    {
        $$ = $1
    }
    | parentendpointid
    {
        $$ = $1
    }
;


RandomField:
    random8
    {
        $$ = $1
    }
    | random16
    {
        $$ = $1
    }
    | random32
    {
        $$ = $1
    }
;

OffsetField:
    packet_i
    {
        $$ = $1
    }
    | packet16_i
    {
        $$ = $1
    }
    | packet32_i
    {
        $$ = $1
    }
    | tcp_Payload_i
    {
        $$ = $1
    }
    | tcp_Payload16_i
    {
        $$ = $1
    }
    | tcp_Payload32_i
    {
        $$ = $1
    }
    | udp_Payload_i
    {
        $$ = $1
    }
    | udp_Payload16_i
    {
        $$ = $1
    }
    | udp_Payload32_i
    {
        $$ = $1
    }
;

Value:
    zero
    {
        $$ = $1
    }
    | TRUE
    {
        $$ = $1
    }
    | FALSE
    {
        $$ = $1
    }
    | TCP_NAME
    {
        $$ = $1
    } 
    | UDP_NAME
    {
        $$ = $1
    }
    | ICMP_NAME
    {
        $$ = $1
    }
    | ICMP6_NAME
    {
        $$ = $1
    }
    | PACKET
    {
        $$ = $1
    }
    | ESTABLISHED
    {
        $$ = $1
    }
    | DELETED
    {
        $$ = $1
    }
    | BIND
    {
        $$ = $1
    }
    | CONECT
    {
        $$ = $1
    }
    | ACCEPT
    {
        $$ = $1
    }
    | LISTEN
    {
        $$ = $1
    }
    | OPEN
    {
        $$ = $1
    }
    | CLOSE
    {
        $$ = $1
    }
    | NETWORK
    {
        $$ = $1
    }
    | NETWORK_FORWARD
    {
        $$ = $1
    }
    | FLOW
    {
        $$ = $1
    }
    | SOCKET
    {
        $$ = $1
    }
    | REFLECT
    {
        $$ = $1
    }
;