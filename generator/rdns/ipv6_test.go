package rdns_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator/rdns"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestIPv6Addr(t *testing.T) {
	handler := rdns.NewIPv6()
	handler.PTRSuffix = "ip6.example.com"
	handler.AllowedSubnets = []*net.IPNet{
		mustParseCIDR("0::/0"),
	}

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
	runRDNSTest(t, handler, "0000-0000-0000-0000-0000-0000-0000-0001.ip6.example.com.", dns.TypeAAAA, &dns.AAAA{
		AAAA: net.ParseIP("::1"),
	})
}

func TestIPv6PTR(t *testing.T) {
	handler := rdns.NewIPv6()
	handler.PTRSuffix = "ip6.example.com"
	handler.AllowedSubnets = []*net.IPNet{
		mustParseCIDR("0::/0"),
	}

	runRDNSTest(t, handler, "4.3.2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, &dns.PTR{
		Ptr: "fe80-0000-0000-0000-0000-0000-0000-0001.ip6.example.com.",
	})
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", dns.TypePTR, &dns.PTR{
		Ptr: "0000-0000-0000-0000-0000-0000-0000-0001.ip6.example.com.",
	})
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.g.f.ip6.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.ff.ip6.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0..0.0.0.0.8.e.ff.ip6.arpa.", dns.TypePTR, nil)
}

func TestIPv6GetZones(t *testing.T) {
	handler := rdns.NewIPv6()
	handler.PTRSuffix = "ip6.example.com"
	handler.AllowedSubnets = []*net.IPNet{
		mustParseCIDR("fe80::/64"),
		mustParseCIDR("fc00::/7"),
	}

	zones := handler.GetZones()
	assert.ElementsMatch(t, []string{
		"0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
		"c.f.ip6.arpa.",
		"d.f.ip6.arpa.",
		"ip6.example.com.",
	}, zones)

	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, &dns.PTR{
		Ptr: "fe80-0000-0000-0000-0000-0000-0000-0001.ip6.example.com.",
	})
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.f.f.ip6.arpa.", dns.TypePTR, nil)

	runRDNSTest(t, handler, "fe80-0-0-0-0-5-6-7.ip6.example.com.", dns.TypeAAAA, &dns.AAAA{
		AAAA: net.ParseIP("fe80:0:0:0:0:5:6:7"),
	})
	runRDNSTest(t, handler, "ff80-1-2-3-4-5-6-7.ip6.example.com.", dns.TypeAAAA, nil)
}
