package generator

import (
	"net"

	"github.com/miekg/dns"
)

type TestResponseWriter struct {
	HadWrites       bool
	LastMsg         *dns.Msg
	LastHandlerName string

	LocalAddrVal  net.Addr
	RemoteAddrVal net.Addr
}

var _ = dns.ResponseWriter(&TestResponseWriter{})

func (w *TestResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.HadWrites = true
	w.LastMsg = msg
	return nil
}

func (w *TestResponseWriter) Close() error {
	w.HadWrites = true
	return nil
}

func (w *TestResponseWriter) Hijack() {
	w.HadWrites = true
}

func (w *TestResponseWriter) Network() string {
	return "udp"
}

func (w *TestResponseWriter) LocalAddr() net.Addr {
	if w.LocalAddrVal == nil {
		return &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 53,
		}
	}
	return w.LocalAddrVal
}

func (w *TestResponseWriter) RemoteAddr() net.Addr {
	if w.RemoteAddrVal == nil {
		return &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 2),
			Port: 5053,
		}
	}
	return w.RemoteAddrVal
}

func (w *TestResponseWriter) TsigStatus() error {
	return nil
}

func (w *TestResponseWriter) TsigTimersOnly(timersOnly bool) {
	w.HadWrites = true
}

func (w *TestResponseWriter) Write(data []byte) (int, error) {
	w.HadWrites = true
	return len(data), nil
}
