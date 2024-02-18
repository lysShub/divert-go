package divert

type Flag uint64

const (
	SNIFF      Flag = 0x0001 // copy data, like pcap
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

//go:generate stringer -output const_gen.go -type=Proto
type Proto uint8

const (
	HOPOPTS  Proto = 0
	ICMP     Proto = 1
	TCP      Proto = 6
	UDP      Proto = 17
	ROUTING  Proto = 43
	FRAGMENT Proto = 44
	AH       Proto = 51
	ICMPV6   Proto = 58
	NONE     Proto = 59
	DSTOPTS  Proto = 60
)
