package util

import "net"

const NetworkLocal = "local"

type Addressable interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type NetworkLocalAddr struct {
	parent net.Addr
}

func (n *NetworkLocalAddr) String() string {
	return NetworkLocal
}

func (n *NetworkLocalAddr) Network() string {
	return NetworkLocal
}

func LocalAddrFromAddr(parent net.Addr) *NetworkLocalAddr {
	localAddr, ok := parent.(*NetworkLocalAddr)
	if ok {
		return localAddr
	}

	return &NetworkLocalAddr{
		parent: parent,
	}
}
