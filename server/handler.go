package server

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type PrometheusDNSHandler struct {
	parent dns.Handler
}

type PrometheusResponseWriter struct {
	parent dns.ResponseWriter
	rcode  int
}

var (
	queriesProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "foxdns_queries_processed_total",
		Help: "The total number of processed DNS queries",
	}, []string{"qtype", "rcode"})

	queryProcessingTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "foxdns_query_processing_time_seconds",
		Help:    "The time it took to process a DNS query",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	})
)

func NewPrometheusDNSHandler(parent dns.Handler) *PrometheusDNSHandler {
	return &PrometheusDNSHandler{
		parent: parent,
	}
}

func (h *PrometheusDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	wproxy := &PrometheusResponseWriter{parent: w}
	startTime := time.Now()
	h.parent.ServeDNS(w, r)
	duration := time.Since(startTime)
	queriesProcessed.WithLabelValues(dns.TypeToString[r.Question[0].Qtype], dns.RcodeToString[wproxy.rcode]).Inc()
	queryProcessingTime.Observe(duration.Seconds())
}

func (w *PrometheusResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.rcode = msg.Rcode
	return w.parent.WriteMsg(msg)
}

func (w *PrometheusResponseWriter) Close() error {
	return w.parent.Close()
}

func (w *PrometheusResponseWriter) Hijack() {
	w.parent.Hijack()
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
