package parse

type Filter struct {
	IfIdx
	IPVersion
}

type IfIdx int

const (
	ANY IfIdx = 0
)

type IPVersion int

const (
	IPV4    IPVersion = 4
	IPV6    IPVersion = 6
	IPV4or6 IPVersion = 0
)

type TransProto int

const (
	TCP  TransProto = 6
	UDP  TransProto = 17
	ICMP TransProto = 1
)
