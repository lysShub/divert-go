# go-divert


golang client for [windivert](https://github.com/basil00/Divert)


[Documnet](https://reqrypt.org/windivert-doc.html)


##### Example:

```golang
package main

import (
	"fmt"
	"log"

	"github.com/lysShub/divert-go"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/header" // go get gvisor.dev/gvisor@go
)

var _ = divert.MustLoad(divert.DLL)

func main() {
	d, err := divert.Open("tcp.Syn and !loopback", divert.Network, 0, divert.Sniff|divert.ReadOnly)
	if err != nil {
		log.Fatal(err)
	}

	var b = make([]byte, 1536)
	var addr divert.Address
	for {
		n, err := d.Recv(b[:cap(b)], &addr)
		if err != nil {
			if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
				continue
			}
			log.Fatal(err)
		} else if n == 0 {
			continue
		}

		if !addr.IPv6() {
			if n >= header.IPv4MinimumSize+header.TCPMinimumSize {
				iphdr := header.IPv4(b[:n])
				tcphdr := header.TCP(iphdr[iphdr.HeaderLength():])

				fmt.Printf("%s:%d --> %s:%d \n",
					iphdr.SourceAddress().String(),
					tcphdr.SourcePort(),
					iphdr.DestinationAddress().String(),
					tcphdr.DestinationPort(),
				)
			}
		} else {
			if n >= header.IPv6MinimumSize+header.TCPMinimumSize {
				iphdr := header.IPv6(b[:n])
				tcphdr := header.TCP(iphdr[header.IPv6MinimumSize:])

				fmt.Printf("%s:%d --> %s:%d \n",
					iphdr.SourceAddress().String(),
					tcphdr.SourcePort(),
					iphdr.DestinationAddress().String(),
					tcphdr.DestinationPort(),
				)
			}
		}
	}
}

```