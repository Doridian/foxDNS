package server

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type PrometheusDNSHandler struct {
	child dns.Handler
}

type PrometheusResponseWriter struct {
	parent        dns.ResponseWriter
	rcode         string
	extendedRCode string
	handlerName   string
}

var (
	queriesProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "foxdns_queries_processed_total",
		Help: "The total number of processed DNS queries",
	}, []string{"qtype", "rcode", "handler", "extended_rcode"})

	queryProcessingTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "foxdns_query_processing_time_seconds",
		Help:    "The time it took to process a DNS query",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	}, []string{"handler"})
)

func NewPrometheusDNSHandler(child dns.Handler) *PrometheusDNSHandler {
	return &PrometheusDNSHandler{
		child: child,
	}
}

func (h *PrometheusDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	wproxy := &PrometheusResponseWriter{
		parent: w,
	}
	startTime := time.Now()
	h.child.ServeDNS(wproxy, r)
	duration := time.Since(startTime)
	queriesProcessed.WithLabelValues(dns.TypeToString[r.Question[0].Qtype], wproxy.rcode, wproxy.handlerName, wproxy.extendedRCode).Inc()
	queryProcessingTime.WithLabelValues(wproxy.handlerName).Observe(duration.Seconds())
}

func (w *PrometheusResponseWriter) WriteMsg(msg *dns.Msg) error {
	if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 {
		w.rcode = "NXRECORD"
	} else {
		w.rcode = dns.RcodeToString[msg.Rcode]
	}

	w.extendedRCode = ""
	edns0 := msg.IsEdns0()
	if edns0 != nil {
		for _, opt := range edns0.Option {
			if opt.Option() != dns.EDNS0EDE {
				continue
			}

			edeOpt, ok := opt.(*dns.EDNS0_EDE)
			if !ok {
				continue
			}
			w.extendedRCode = dns.ExtendedErrorCodeToString[edeOpt.InfoCode]
			break
		}
	}

	return w.parent.WriteMsg(msg)
}

func (w *PrometheusResponseWriter) SetHandlerName(name string) {
	w.handlerName = name
}

func (w *PrometheusResponseWriter) Close() error {
	return w.parent.Close()
}

func (w *PrometheusResponseWriter) Hijack() {
	w.parent.Hijack()
}

func (w *PrometheusResponseWriter) Network() string {
	return w.parent.Network()
}

func (w *PrometheusResponseWriter) LocalAddr() net.Addr {
	return w.parent.LocalAddr()
}

func (w *PrometheusResponseWriter) RemoteAddr() net.Addr {
	return w.parent.RemoteAddr()
}

func (w *PrometheusResponseWriter) TsigStatus() error {
	return w.parent.TsigStatus()
}

func (w *PrometheusResponseWriter) TsigTimersOnly(timersOnly bool) {
	w.parent.TsigTimersOnly(timersOnly)
}

func (w *PrometheusResponseWriter) Write(data []byte) (int, error) {
	return w.parent.Write(data)
}
