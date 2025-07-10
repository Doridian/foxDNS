package util

import (
	"errors"
	"net"

	"github.com/miekg/dns"
)

type SimpleDNSResponseWriter interface {
	// LocalAddr returns the net.Addr of the server
	LocalAddr() net.Addr
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
	// Network returns the network type (e.g., "udp", "tcp") of the connection.
	Network() string
}

type DNSResponseWriter struct {
	parent             SimpleDNSResponseWriter
	remoteAddrOverride net.Addr

	Result *dns.Msg
}

func NewResponseWriter(parent SimpleDNSResponseWriter, remoteAddrOverride net.Addr) *DNSResponseWriter {
	return &DNSResponseWriter{
		parent: parent,
	}
}

func (*DNSResponseWriter) Close() error {
	return nil
}

func (*DNSResponseWriter) Hijack() {
	panic("unimplemented")
}

func (r *DNSResponseWriter) Network() string {
	return r.parent.Network()
}

func (r *DNSResponseWriter) LocalAddr() net.Addr {
	return r.parent.LocalAddr()
}

func (r *DNSResponseWriter) RemoteAddr() net.Addr {
	if r.remoteAddrOverride != nil {
		return r.remoteAddrOverride
	}
	return r.parent.RemoteAddr()
}

func (*DNSResponseWriter) TsigStatus() error {
	return errors.New("unimplemented")
}

func (*DNSResponseWriter) TsigTimersOnly(bool) {

}

func (*DNSResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("Write called")
}

func (r *DNSResponseWriter) WriteMsg(msg *dns.Msg) error {
	if r.Result != nil {
		return errors.New("WriteMsg called twice")
	}
	r.Result = msg
	return nil
}
