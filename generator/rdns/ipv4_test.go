package rdns_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator/rdns"
	"github.com/miekg/dns"
)

func TestIPv4(t *testing.T) {
	handler := rdns.NewIPv4()
	handler.PTRSuffix = "ip4.example.com"

	runRDNSTest(t, handler, "1-2-3-4.ip4.example.com", dns.TypeA, &dns.A{
		A: net.IPv4(1, 2, 3, 4).To4(),
	})
	runRDNSTest(t, handler, "999-2-3-4.ip4.example.com", dns.TypeA, nil)
	runRDNSTest(t, handler, "1-2-3-4.ip4.example.com", dns.TypeAAAA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip4.example.com", dns.TypeA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip4.example.com", dns.TypeAAAA, nil)
}
