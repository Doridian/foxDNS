package resolver_test

import (
	"net"
	"testing"
	"time"

	"github.com/Doridian/foxDNS/handler"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestExistingRecordWithCache(t *testing.T) {
	emptyZoneHandler := loadSimpleZone(emptyZone)

	timeBegin := time.Now()
	fakedTime := timeBegin
	resolverGenerator.CurrentTime = func() time.Time {
		return fakedTime
	}

	testWriter := &handler.TestResponseWriter{}
	qmsg := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}
	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.True(t, testWriter.HadWrites)
	assert.Equal(t, dns.RcodeSuccess, testWriter.LastMsg.Rcode)
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
	}, testWriter.LastMsg.Answer)
	assert.ElementsMatch(t, []dns.RR{}, testWriter.LastMsg.Ns)

	// Empty out zone such that any returned A record must come from cache
	dummyServer.SetHandler(emptyZoneHandler)

	// Fake time 0.8 seconds ahead to test TTL countdown not tripping just yet
	fakedTime = timeBegin.Add(800 * time.Millisecond)

	testWriter = &handler.TestResponseWriter{}
	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.True(t, testWriter.HadWrites)
	assert.Equal(t, dns.RcodeSuccess, testWriter.LastMsg.Rcode)
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
	}, testWriter.LastMsg.Answer)
	assert.ElementsMatch(t, []dns.RR{}, testWriter.LastMsg.Ns)

	// Fake time 3.1 seconds ahead to test TTL countdown
	fakedTime = timeBegin.Add(3100 * time.Millisecond)

	testWriter = &handler.TestResponseWriter{}
	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.True(t, testWriter.HadWrites)
	assert.Equal(t, dns.RcodeSuccess, testWriter.LastMsg.Rcode)
	assert.ElementsMatch(t, []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      2,
				Rdlength: 4,
			},
			A: net.ParseIP("10.13.37.0").To4(),
		},
	}, testWriter.LastMsg.Answer)
	assert.ElementsMatch(t, []dns.RR{}, testWriter.LastMsg.Ns)

	// Fake time 6 secodns ahead to force record to be uncached
	fakedTime = timeBegin.Add(6 * time.Second)

	testWriter = &handler.TestResponseWriter{}
	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.True(t, testWriter.HadWrites)
	assert.Equal(t, dns.RcodeSuccess, testWriter.LastMsg.Rcode)
	assert.ElementsMatch(t, []dns.RR{}, testWriter.LastMsg.Answer)
	assert.ElementsMatch(t, []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeSOA,
				Class:    dns.ClassINET,
				Ttl:      5,
				Rdlength: 39,
			},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  300,
		},
	}, testWriter.LastMsg.Ns)

	resolverGenerator.CurrentTime = time.Now
}
