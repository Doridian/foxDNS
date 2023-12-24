package resolver_test

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestExistingRecord(t *testing.T) {
	response := queryResolver(t, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})

	assert.Equal(t, dns.RcodeSuccess, response.Rcode)
	assert.ElementsMatch(t, []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      5,
				Rdlength: 4,
			},
			A: net.ParseIP("10.13.37.0").To4(),
		},
	}, response.Answer)
	assert.ElementsMatch(t, []dns.RR{}, response.Ns)
}

func TestNonExistingRecord(t *testing.T) {
	response := queryResolver(t, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeMX,
		Qclass: dns.ClassINET,
	})

	assert.Equal(t, dns.RcodeSuccess, response.Rcode)
	assert.ElementsMatch(t, []dns.RR{}, response.Answer)
	assert.ElementsMatch(t, []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeSOA,
				Class:    dns.ClassINET,
				Ttl:      5,
				Rdlength: 61,
			},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  300,
		},
	}, response.Ns)
}

func TestNXDOMAIN(t *testing.T) {
	response := queryResolver(t, dns.Question{
		Name:   "nx.example.com.",
		Qtype:  dns.TypeMX,
		Qclass: dns.ClassINET,
	})

	assert.Equal(t, dns.RcodeNameError, response.Rcode)
	assert.ElementsMatch(t, []dns.RR{}, response.Answer)
	assert.ElementsMatch(t, []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeSOA,
				Class:    dns.ClassINET,
				Ttl:      5,
				Rdlength: 61,
			},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  300,
		},
	}, response.Ns)
}

func TestRefusesNonINET(t *testing.T) {
	response := queryResolver(t, dns.Question{
		Name:   "nx.example.com.",
		Qtype:  dns.TypeMX,
		Qclass: dns.ClassCHAOS,
	})

	assert.Equal(t, dns.RcodeRefused, response.Rcode)
	assert.Empty(t, response.Answer)
	assert.Empty(t, response.Ns)
}
