package rdns_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator/rdns"
	"github.com/miekg/dns"
)

func TestIPv6Addr(t *testing.T) {
	handler := rdns.NewIPv6()
	handler.PTRSuffix = "ip6.example.com"

	runRDNSTest(t, handler, "1-2-3-4.ip6.example.com.", dns.TypeA, nil)
	runRDNSTest(t, handler, "1-2-3-4.ip6.example.com.", dns.TypeAAAA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip6.example.com.", dns.TypeA, nil)
	runRDNSTest(t, handler, "fee80-1-2-3-4-5-6-7.ip6.example.com.", dns.TypeAAAA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip6.example.com.", dns.TypeAAAA, &dns.AAAA{
		AAAA: net.ParseIP("fe80:1:2:3:4:5:6:7"),
	})
	runRDNSTest(t, handler, "fe80--1.ip6.example.com.", dns.TypeAAAA, &dns.AAAA{
		AAAA: net.ParseIP("fe80::1"),
	})
}

func TestIPv6PTR(t *testing.T) {
	handler := rdns.NewIPv6()
	handler.PTRSuffix = "ip6.example.com"

	runRDNSTest(t, handler, "4.3.2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, &dns.PTR{
		Ptr: "fe80--1.ip6.example.com.",
	})
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.g.f.ip6.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, nil)
}
