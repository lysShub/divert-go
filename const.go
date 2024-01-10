package divert

type Flag uint64

const (
	SNIFF      Flag = 0x0001
	DROP       Flag = 0x0002
	RECV_ONLY  Flag = 0x0004
	READ_ONLY  Flag = RECV_ONLY
	SEND_ONLY  Flag = 0x0008
	WRITE_ONLY Flag = SEND_ONLY
	NO_INSTALL Flag = 0x0010
	FRAGMENTS  Flag = 0x0020
)

type Event uint8

func (e Event) String() (layer string, op string) {
	switch e {
	case NETWORK_PACKET:
		return "network", "packet"
	case FLOW_ESTABLISHED:
		return "flow", "established"
	case FLOW_DELETED:
		return "flow", "deleted"
	case SOCKET_BIND:
		return "socket", "bind"
	case SOCKET_CONNECT:
		return "socket", "connect"
	case SOCKET_LISTEN:
		return "socket", "listen"
	case SOCKET_ACCEPT:
		return "socket", "accept"
	case SOCKET_CLOSE:
		return "socket", "close"
	case REFLECT_OPEN:
		return "reflect", "open"
	case REFLECT_CLOSE:
		return "reflect", "close"
	default:
		return "unknown", "unknown"
	}
}

const (
	NETWORK_PACKET   Event = iota /* Network packet. */
	FLOW_ESTABLISHED              /* Flow established. */
	FLOW_DELETED                  /* Flow deleted. */
	SOCKET_BIND                   /* Socket bind. */
	SOCKET_CONNECT                /* Socket connect. */
	SOCKET_LISTEN                 /* Socket listen. */
	SOCKET_ACCEPT                 /* Socket accept. */
	SOCKET_CLOSE                  /* Socket close. */
	REFLECT_OPEN                  /* WinDivert handle opened. */
	REFLECT_CLOSE                 /* WinDivert handle closed. */
)

type Proto uint8

const (
	IPPROTO_HOPOPTS  Proto = iota // IPv6 Hop-by-Hop options
	IPPROTO_ICMP           = 1
	IPPROTO_IGMP           = 2
	IPPROTO_GGP            = 3
	IPPROTO_IPV4           = 4
	IPPROTO_ST             = 5
	IPPROTO_TCP            = 6
	IPPROTO_CBT            = 7
	IPPROTO_EGP            = 8
	IPPROTO_IGP            = 9
	IPPROTO_PUP            = 12
	IPPROTO_UDP            = 17
	IPPROTO_IDP            = 22
	IPPROTO_RDP            = 27
	IPPROTO_IPV6           = 41 // IPv6 header
	IPPROTO_ROUTING        = 43 // IPv6 Routing header
	IPPROTO_FRAGMENT       = 44 // IPv6 fragmentation header
	IPPROTO_ESP            = 50 // encapsulating security payload
	IPPROTO_AH             = 51 // authentication header
	IPPROTO_ICMPV6         = 58 // ICMPv6
	IPPROTO_NONE           = 59 // IPv6 no next header
	IPPROTO_DSTOPTS        = 60 // IPv6 Destination options
	IPPROTO_ND             = 77
	IPPROTO_ICLFXBM        = 78
	IPPROTO_PIM            = 103
	IPPROTO_PGM            = 113
	IPPROTO_L2TP           = 115
	IPPROTO_SCTP           = 132
	IPPROTO_RAW            = 255
	IPPROTO_MAX            = 256
)

func (p Proto) String() string {
	switch p {
	case IPPROTO_HOPOPTS:
		return "IPv6 Hop-by-Hop options"
	case IPPROTO_ICMP:
		return "ICMP"
	case IPPROTO_IGMP:
		return "IGMP"
	case IPPROTO_GGP:
		return "GGP"
	case IPPROTO_IPV4:
		return "IPv4"
	case IPPROTO_ST:
		return "ST"
	case IPPROTO_TCP:
		return "TCP"
	case IPPROTO_CBT:
		return "CBT"
	case IPPROTO_EGP:
		return "EGP"
	case IPPROTO_IGP:
		return "IGP"
	case IPPROTO_PUP:
		return "PUP"
	case IPPROTO_UDP:
		return "UDP"
	case IPPROTO_IDP:
		return "IDP"
	case IPPROTO_RDP:
		return "RDP"
	case IPPROTO_IPV6:
		return "IPv6 header"
	case IPPROTO_ROUTING:
		return "IPv6 Routing header"
	case IPPROTO_FRAGMENT:
		return "IPv6 fragmentation header"
	case IPPROTO_ESP:
		return "encapsulating security payload"
	case IPPROTO_AH:
		return "authentication header"
	case IPPROTO_ICMPV6:
		return "ICMPv6"
	case IPPROTO_NONE:
		return "IPv6 no next header"
	case IPPROTO_DSTOPTS:
		return "IPv6 Destination options"
	case IPPROTO_ND:
		return "ND"
	case IPPROTO_ICLFXBM:
		return "ICLFXBM"
	case IPPROTO_PIM:
		return "PIM"
	case IPPROTO_PGM:
		return "PGM"
	case IPPROTO_L2TP:
		return "L2TP"
	case IPPROTO_SCTP:
		return "SCTP"
	case IPPROTO_RAW:
		return "RAW"
	default:
		return "unknown protocol"
	}
}
