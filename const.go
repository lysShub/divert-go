package divert

import "fmt"

//go:generate stringer -linecomment -output const_gen.go -type=Layer,Proto

type Layer uint8

var _ = Layer(0).String()

const (
	Network Layer = iota
	NetworkForward
	Flow
	Socket
	Reflect
	Unknown
)

type Flag uint64

const (
	Sniff     Flag = 0x0001 // copy data, like pcap
	Drop      Flag = 0x0002
	RecvOnly  Flag = 0x0004
	ReadOnly  Flag = RecvOnly
	SendOnly  Flag = 0x0008
	WriteOnly Flag = SendOnly
	NoInstall Flag = 0x0010
	Fragments Flag = 0x0020
)

type Event uint8

func (e Event) Layer() Layer {
	switch e {
	case NetworkPacket:
		return Network
	case FlowEstablishd:
		return Flow
	case FlowDeleted:
		return Flow
	case SocketBind:
		return Socket
	case SocketConnect:
		return Socket
	case SocketListen:
		return Socket
	case SocketAccept:
		return Socket
	case SocketClose:
		return Socket
	case ReflectOpen:
		return Reflect
	case ReflectClose:
		return Reflect
	default:
		return Unknown
	}
}

func (e Event) Op() string {
	switch e {
	case NetworkPacket:
		return "packet"
	case FlowEstablishd:
		return "established"
	case FlowDeleted:
		return "deleted"
	case SocketBind:
		return "bind"
	case SocketConnect:
		return "connect"
	case SocketListen:
		return "listen"
	case SocketAccept:
		return "accept"
	case SocketClose:
		return "close"
	case ReflectOpen:
		return "open"
	case ReflectClose:
		return "close"
	default:
		return "unknown"
	}
}

func (e Event) String() string {
	return fmt.Sprintf("%s_%s", e.Layer(), e.Op())
}

const (
	NetworkPacket  Event = iota /* Network packet. */
	FlowEstablishd              /* Flow established. */
	FlowDeleted                 /* Flow deleted. */
	SocketBind                  /* Socket bind. */
	SocketConnect               /* Socket connect. */
	SocketListen                /* Socket listen. */
	SocketAccept                /* Socket accept. */
	SocketClose                 /* Socket close. */
	ReflectOpen                 /* WinDivert handle opened. */
	ReflectClose                /* WinDivert handle closed. */
)

type Proto uint8

var _ = Proto(0).String()

const (
	HOPOPTS  Proto = 0  // hopopts
	ICMP     Proto = 1  // icmp
	TCP      Proto = 6  // tcp
	UDP      Proto = 17 // udp
	ROUTING  Proto = 43 // routing
	FRAGMENT Proto = 44 // fragment
	AH       Proto = 51 // ah
	ICMPV6   Proto = 58 // icmpv6
	NONE     Proto = 59 // none
	DSTOPTS  Proto = 60 // dstopts
)

type PARAM uint32

const (
	QueueLength  PARAM = iota /* Packet queue length. */
	QueueTime                 /* Packet queue time. */
	QueueSize                 /* Packet queue size. */
	VersionMajor              /* Driver version (major). */
	VersionMinor              /* Driver version (minor). */
)

type Shutdown uint32

const (
	Recv Shutdown = iota + 1 /* Shutdown recv. */
	Send                     /* Shutdown send. */
	Both                     /* Shutdown recv and send. */
)
