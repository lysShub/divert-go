# go-divert


golang client for [windivert](https://github.com/basil00/Divert)




##### Example:

```golang
package main

import (
	"fmt"
	"log"

	"github.com/lysShub/divert-go"
	"gvisor.dev/gvisor/pkg/tcpip/header" // go get gvisor.dev/gvisor@go
)

func main() {
	divert.Load(divert.Mem)
	defer divert.Release()

	d, err := divert.Open("tcp.Syn and !loopback", divert.Network, 0, divert.Sniff|divert.ReadOnly)
	if err != nil {
		log.Fatal(err)
	}

	var b = make([]byte, 1536)
	var addr divert.Address
	for {
		n, err := d.Recv(b[:cap(b)], &addr)
		if err != nil {
			log.Fatal(err)
		}

		if !addr.IPv6() {
			if n >= header.IPv4MinimumSize+header.TCPMinimumSize {
				ipHdr := header.IPv4(b[:n])
				tcpHdr := header.TCP(ipHdr[ipHdr.HeaderLength():])

				fmt.Printf("%s:%d --> %s:%d \n",
					ipHdr.SourceAddress().String(),
					tcpHdr.SourcePort(),
					ipHdr.DestinationAddress().String(),
					tcpHdr.DestinationPort(),
				)
			}
		} else {
			if n >= header.IPv6MinimumSize+header.TCPMinimumSize {
				ipHdr := header.IPv6(b[:n])
				tcpHdr := header.TCP(ipHdr[header.IPv6MinimumSize:])

				fmt.Printf("%s:%d --> %s:%d \n",
					ipHdr.SourceAddress().String(),
					tcpHdr.SourcePort(),
					ipHdr.DestinationAddress().String(),
					tcpHdr.DestinationPort(),
				)
			}
		}
	}
}
```