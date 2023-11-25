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
TOKEN_EVENT_ACCEPT         "accept"           
TOKEN_EVENT_BIND           "bind"             
TOKEN_EVENT_CLOSE          "close"            
TOKEN_EVENT_CONNECT        "connect"          
TOKEN_EVENT_DELETED        "deleted"          
TOKEN_EVENT_ESTABLISHED    "established"      
TOKEN_MACRO_FALSE          "false"            
TOKEN_FLOW                 "flow"             
TOKEN_MACRO_ICMP           "icmp"             
TOKEN_MACRO_ICMPV6         "icmpv6"           
TOKEN_EVENT_LISTEN         "listen"           
TOKEN_NETWORK              "network"          
TOKEN_NETWORK_FORWARD      "network_forward"  
TOKEN_EVENT_OPEN           "open"             
TOKEN_EVENT_PACKET         "packet"           
TOKEN_REFLECT              "reflect"          
TOKEN_SOCKET               "socket"           
TOKEN_MACRO_TCP            "tcp"              
TOKEN_MACRO_TRUE           "true"             
TOKEN_MACRO_UDP            "udp"              
TOKEN_AND                  "and"              
TOKEN_ENDPOINT_ID          "endpointId"       
TOKEN_EVENT                "event"            
TOKEN_FALSE                "false"            
TOKEN_FRAGMENT             "fragment"         
TOKEN_ICMP                 "icmp"             
TOKEN_ICMP_BODY            "icmp.Body"        
TOKEN_ICMP_CHECKSUM        "icmp.Checksum"    
TOKEN_ICMP_CODE            "icmp.Code"        
TOKEN_ICMP_TYPE            "icmp.Type"        
TOKEN_ICMPV6               "icmpv6"           
TOKEN_ICMPV6_BODY          "icmpv6.Body"      
TOKEN_ICMPV6_CHECKSUM      "icmpv6.Checksum"  
TOKEN_ICMPV6_CODE          "icmpv6.Code"      
TOKEN_ICMPV6_TYPE          "icmpv6.Type"      
TOKEN_IF_IDX               "ifIdx"            
TOKEN_IMPOSTOR             "impostor"         
TOKEN_INBOUND              "inbound"          
TOKEN_IP                   "ip"               
TOKEN_IP_CHECKSUM          "ip.Checksum"      
TOKEN_IP_DF                "ip.DF"            
TOKEN_IP_DST_ADDR          "ip.DstAddr"       
TOKEN_IP_FRAG_OFF          "ip.FragOff"       
TOKEN_IP_HDR_LENGTH        "ip.HdrLength"     
TOKEN_IP_ID                "ip.Id"            
TOKEN_IP_LENGTH            "ip.Length"        
TOKEN_IP_MF                "ip.MF"            
TOKEN_IP_PROTOCOL          "ip.Protocol"      
TOKEN_IP_SRC_ADDR          "ip.SrcAddr"       
TOKEN_IP_TOS               "ip.TOS"           
TOKEN_IP_TTL               "ip.TTL"           
TOKEN_IPV6                 "ipv6"             
TOKEN_IPV6_DST_ADDR        "ipv6.DstAddr"     
TOKEN_IPV6_FLOW_LABEL      "ipv6.FlowLabel"   
TOKEN_IPV6_HOP_LIMIT       "ipv6.HopLimit"    
TOKEN_IPV6_LENGTH          "ipv6.Length"      
TOKEN_IPV6_NEXT_HDR        "ipv6.NextHdr"     
TOKEN_IPV6_SRC_ADDR        "ipv6.SrcAddr"     
TOKEN_IPV6_TRAFFIC_CLASS   "ipv6.TrafficClass"
TOKEN_LAYER                "layer"            
TOKEN_LENGTH               "length"           
TOKEN_LOCAL_ADDR           "localAddr"        
TOKEN_LOCAL_PORT           "localPort"        
TOKEN_LOOPBACK             "loopback"         
TOKEN_NOT                  "not"              
TOKEN_OR                   "or"               
TOKEN_OUTBOUND             "outbound"         
TOKEN_PACKET               "packet"           
TOKEN_PACKET16             "packet16"         
TOKEN_PACKET32             "packet32"         
TOKEN_PARENT_ENDPOINT_ID   "parentEndpointId" 
TOKEN_PRIORITY             "priority"         
TOKEN_PROCESS_ID           "processId"        
TOKEN_PROTOCOL             "protocol"         
TOKEN_RANDOM16             "random16"         
TOKEN_RANDOM32             "random32"         
TOKEN_RANDOM8              "random8"          
TOKEN_REMOTE_ADDR          "remoteAddr"       
TOKEN_REMOTE_PORT          "remotePort"       
TOKEN_SUB_IF_IDX           "subIfIdx"         
TOKEN_TCP                  "tcp"              
TOKEN_TCP_ACK              "tcp.Ack"          
TOKEN_TCP_ACK_NUM          "tcp.AckNum"       
TOKEN_TCP_CHECKSUM         "tcp.Checksum"     
TOKEN_TCP_DST_PORT         "tcp.DstPort"      
TOKEN_TCP_FIN              "tcp.Fin"          
TOKEN_TCP_HDR_LENGTH       "tcp.HdrLength"    
TOKEN_TCP_PAYLOAD          "tcp.Payload"      
TOKEN_TCP_PAYLOAD16        "tcp.Payload16"    
TOKEN_TCP_PAYLOAD32        "tcp.Payload32"    
TOKEN_TCP_PAYLOAD_LENGTH   "tcp.PayloadLength"
TOKEN_TCP_PSH              "tcp.Psh"          
TOKEN_TCP_RST              "tcp.Rst"          
TOKEN_TCP_SEQ_NUM          "tcp.SeqNum"       
TOKEN_TCP_SRC_PORT         "tcp.SrcPort"      
TOKEN_TCP_SYN              "tcp.Syn"          
TOKEN_TCP_URG              "tcp.Urg"          
TOKEN_TCP_URG_PTR          "tcp.UrgPtr"       
TOKEN_TCP_WINDOW           "tcp.Window"       
TOKEN_TIMESTAMP            "timestamp"        
TOKEN_TRUE                 "true"             
TOKEN_UDP                  "udp"              
TOKEN_UDP_CHECKSUM         "udp.Checksum"     
TOKEN_UDP_DST_PORT         "udp.DstPort"      
TOKEN_UDP_LENGTH           "udp.Length"       
TOKEN_UDP_PAYLOAD          "udp.Payload"      
TOKEN_UDP_PAYLOAD16        "udp.Payload16"    
TOKEN_UDP_PAYLOAD32        "udp.Payload32"    
TOKEN_UDP_PAYLOAD_LENGTH   "udp.PayloadLength"
TOKEN_UDP_SRC_PORT         "udp.SrcPort"      
TOKEN_ZERO                 "zero"             
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