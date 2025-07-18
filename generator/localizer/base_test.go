package localizer_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator/localizer"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func runLocalizerTest(t *testing.T, host string, qtype uint16, remoteIP net.IP, rewrites []localizer.LocalizerRewrite, expected dns.RR) {
	handler := localizer.New()
	assert.NoError(t, handler.AddRewrites(rewrites))
	assert.NoError(t, handler.AddRecord("example.com", "0.0.1.2/16"))
	assert.NoError(t, handler.AddRecord("example.com", "fe80::1/64"))
	assert.NoError(t, handler.AddRecord("v4.example.com", "0.0.1.2/16"))
	assert.NoError(t, handler.AddRecord("v6.example.com", "fe80::1/64"))

	rr, _, _, rcode := handler.HandleQuestion(&dns.Question{
		Name:   host,
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}, remoteIP)
	assert.Equal(t, dns.RcodeSuccess, rcode)

	if expected == nil {
		assert.Empty(t, rr)
	} else {
		assert.ElementsMatch(t, []dns.RR{
			util.FillHeader(expected, host, qtype, 60),
		}, rr)
	}
}

func TestAFromIPv4(t *testing.T) {
	runLocalizerTest(t, "example.com.", dns.TypeA, net.IPv4(10, 99, 3, 4).To4(), nil, &dns.A{
		A: net.IPv4(10, 99, 1, 2).To4(),
	})
}

func TestAFromIPv4WithRewrite(t *testing.T) {
	// Test that the rewrite is applied
	runLocalizerTest(t, "example.com.", dns.TypeA, net.IPv4(10, 100, 3, 4).To4(), []localizer.LocalizerRewrite{
		{
			From: "10.100.0.0/16",
			To:   "10.99.0.0/16",
		},
	}, &dns.A{
		A: net.IPv4(10, 99, 1, 2).To4(),
	})

	// Test that the rewrite is not applied because out-of-subnet
	runLocalizerTest(t, "example.com.", dns.TypeA, net.IPv4(10, 101, 3, 4).To4(), []localizer.LocalizerRewrite{
		{
			From: "10.100.0.0/16",
			To:   "10.99.0.0/16",
		},
	}, &dns.A{
		A: net.IPv4(10, 101, 1, 2).To4(),
	})
}

func TestAFromIPv6(t *testing.T) {
	runLocalizerTest(t, "example.com.", dns.TypeA, net.IPv6loopback, nil, nil)
}

func TestAAAAFromIPv4(t *testing.T) {
	runLocalizerTest(t, "example.com.", dns.TypeAAAA, net.IPv4(10, 99, 3, 4).To4(), nil, nil)
}

func TestAAAAFromIPv6(t *testing.T) {
	runLocalizerTest(t, "example.com.", dns.TypeAAAA, net.ParseIP("fd00:abcd::1234:1"), nil, &dns.AAAA{
		AAAA: net.ParseIP("fd00:abcd::1"),
	})
}

func TestAAAAFromIPv6WithRewrite(t *testing.T) {
	// Test that the rewrite is applied
	runLocalizerTest(t, "example.com.", dns.TypeAAAA, net.ParseIP("fe00:abcd::1234:1"), []localizer.LocalizerRewrite{
		{
			From: "fe00::/8",
			To:   "fd00::/8",
		},
	}, &dns.AAAA{
		AAAA: net.ParseIP("fd00:abcd::1"),
	})

	// Test that the rewrite is not applied because out-of-subnet
	runLocalizerTest(t, "example.com.", dns.TypeAAAA, net.ParseIP("fc00:abcd::1234:1"), []localizer.LocalizerRewrite{
		{
			From: "fe00::/8",
			To:   "fd00::/8",
		},
	}, &dns.AAAA{
		AAAA: net.ParseIP("fc00:abcd::1"),
	})
}
