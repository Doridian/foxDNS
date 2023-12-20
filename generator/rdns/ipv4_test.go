package rdns_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator/rdns"
	"github.com/miekg/dns"
)

func TestIPv4Addr(t *testing.T) {
	handler := rdns.NewIPv4()
	handler.PTRSuffix = "ip4.example.com"

	runRDNSTest(t, handler, "1-2-3-4.ip4.example.com.", dns.TypeA, &dns.A{
		A: net.IPv4(1, 2, 3, 4).To4(),
	})
	runRDNSTest(t, handler, "999-2-3-4.ip4.example.com.", dns.TypeA, nil)
	runRDNSTest(t, handler, "1-2-3-4.ip4.example.com.", dns.TypeAAAA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip4.example.com.", dns.TypeA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip4.example.com.", dns.TypeAAAA, nil)
}

func TestIPv4PTR(t *testing.T) {
	handler := rdns.NewIPv4()
	handler.PTRSuffix = "ip4.example.com"

	runRDNSTest(t, handler, "4.3.2.1.in-addr.arpa.", dns.TypePTR, &dns.PTR{
		Ptr: "1-2-3-4.ip4.example.com.",
	})
	runRDNSTest(t, handler, "999.3.2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "5.4.3.2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "3.2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "4..2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, nil)
}
