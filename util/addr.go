package util

import "net"

const NetworkLocal = "local"

type Addressable interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type NetworkLocalAddr struct {
	Parent net.Addr
}

func (n *NetworkLocalAddr) String() string {
	return NetworkLocal
}

func (n *NetworkLocalAddr) Network() string {
	return NetworkLocal
}
