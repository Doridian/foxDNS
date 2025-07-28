package util

import (
	"net"
)

type DummyAddressable struct {
	RemoteAddress net.Addr
}

func (d *DummyAddressable) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (d *DummyAddressable) RemoteAddr() net.Addr {
	return d.RemoteAddress
}

func (d *DummyAddressable) Network() string {
	return NetworkLocal
}
