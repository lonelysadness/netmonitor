// base.go

package nfqueue

import (
	"net"
	"time"
)

type Base struct {
	Src      net.IP
	Dst      net.IP
	SeenAt   time.Time
	Inbound  bool
	Protocol uint8
}

func (b *Base) Info() *Base {
	return b
}

