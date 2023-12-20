package rdns_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator/rdns"
	"github.com/miekg/dns"
)

func TestIPv6(t *testing.T) {
	handler := rdns.NewIPv6()
	handler.PTRSuffix = "ip6.example.com"

	runRDNSTest(t, handler, "1-2-3-4.ip6.example.com", dns.TypeA, nil)
	runRDNSTest(t, handler, "1-2-3-4.ip6.example.com", dns.TypeAAAA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip6.example.com", dns.TypeA, nil)
	runRDNSTest(t, handler, "fee80-1-2-3-4-5-6-7.ip6.example.com", dns.TypeAAAA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip6.example.com", dns.TypeAAAA, &dns.AAAA{
		AAAA: net.ParseIP("fe80:1:2:3:4:5:6:7"),
	})
}
