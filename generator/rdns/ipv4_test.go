package rdns_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator/rdns"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestIPv4Addr(t *testing.T) {
	handler := rdns.NewIPv4()
	handler.SetPTRSuffix("ip4.example.com")
	handler.AllowedSubnets = []*net.IPNet{
		mustParseCIDR("0.0.0.0/0"),
	}

	runRDNSTest(t, handler, "1-2-3-4.ip4.example.com.", dns.TypeA, &dns.A{
		A: net.IPv4(1, 2, 3, 4).To4(),
	})
	runRDNSTest(t, handler, "1--3-4.ip4.example.com.", dns.TypeA, nil)
	runRDNSTest(t, handler, "999-2-3-4.ip4.example.com.", dns.TypeA, nil)
	runRDNSTest(t, handler, "1-2-3-4.ip4.example.com.", dns.TypeAAAA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip4.example.com.", dns.TypeA, nil)
	runRDNSTest(t, handler, "fe80-1-2-3-4-5-6-7.ip4.example.com.", dns.TypeAAAA, nil)
}

func TestIPv4PTR(t *testing.T) {
	handler := rdns.NewIPv4()
	handler.SetPTRSuffix("ip4.example.com")
	handler.AllowedSubnets = []*net.IPNet{
		mustParseCIDR("0.0.0.0/0"),
	}

	runRDNSTest(t, handler, "4.3.2.1.in-addr.arpa.", dns.TypePTR, &dns.PTR{
		Ptr: "1-2-3-4.ip4.example.com.",
	})
	runRDNSTest(t, handler, "999.3.2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "5.4.3.2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "3.2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "4..2.1.in-addr.arpa.", dns.TypePTR, nil)
	runRDNSTest(t, handler, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", dns.TypePTR, nil)
}

func TestIPv4GetZones(t *testing.T) {
	handler := rdns.NewIPv4()
	handler.SetPTRSuffix("ip4.example.com")
	handler.AllowedSubnets = []*net.IPNet{
		mustParseCIDR("10.0.0.0/8"),
		mustParseCIDR("192.168.0.0/16"),
		mustParseCIDR("172.16.0.0/12"),
	}

	zones := handler.GetPTRZones()
	assert.ElementsMatch(t, []string{
		"10.in-addr.arpa.",
		"16.172.in-addr.arpa.",
		"17.172.in-addr.arpa.",
		"18.172.in-addr.arpa.",
		"19.172.in-addr.arpa.",
		"20.172.in-addr.arpa.",
		"21.172.in-addr.arpa.",
		"22.172.in-addr.arpa.",
		"23.172.in-addr.arpa.",
		"24.172.in-addr.arpa.",
		"25.172.in-addr.arpa.",
		"26.172.in-addr.arpa.",
		"27.172.in-addr.arpa.",
		"28.172.in-addr.arpa.",
		"29.172.in-addr.arpa.",
		"30.172.in-addr.arpa.",
		"31.172.in-addr.arpa.",
		"168.192.in-addr.arpa.",
	}, zones)
	assert.Equal(t, "ip4.example.com.", handler.GetAddrZone())

	runRDNSTest(t, handler, "3.2.1.10.in-addr.arpa.", dns.TypePTR, &dns.PTR{
		Ptr: "10-1-2-3.ip4.example.com.",
	})
	runRDNSTest(t, handler, "3.2.1.11.in-addr.arpa.", dns.TypePTR, nil)

	runRDNSTest(t, handler, "10-1-2-3.ip4.example.com.", dns.TypeA, &dns.A{
		A: net.ParseIP("10.1.2.3").To4(),
	})
	runRDNSTest(t, handler, "11-1-2-3.ip4.example.com.", dns.TypeA, nil)
}
