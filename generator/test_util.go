package generator

import (
	"net"

	"github.com/miekg/dns"
)

type TestResponseWriter struct {
	HadWrites       bool
	LastMsg         *dns.Msg
	LastHandlerName string
}

var _ = dns.ResponseWriter(&TestResponseWriter{})

func (w *TestResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.HadWrites = true
	w.LastMsg = msg
	return nil
}

func (w *TestResponseWriter) SetHandlerName(name string) {
	w.HadWrites = true
	w.LastHandlerName = name
}

func (w *TestResponseWriter) Close() error {
	w.HadWrites = true
	return nil
}

func (w *TestResponseWriter) Hijack() {
	w.HadWrites = true
}

func (w *TestResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 53,
	}
}

func (w *TestResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 5053,
	}
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
