package resolver_test

import (
	"bytes"
	"net"
	"time"

	"github.com/Doridian/foxDNS/handler"
	"github.com/Doridian/foxDNS/handler/resolver"
	"github.com/Doridian/foxDNS/handler/static"
	"github.com/Doridian/foxDNS/server"
	"github.com/miekg/dns"
)

const dummyZone = "$TTL 5\n@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 604800 300\n@ IN NS ns1.example.com.\n@ IN NS ns2.example.com.\n@ IN A 10.13.37.0"
const emptyZone = "$TTL 5\n@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 604800 300\n@ IN NS ns1.example.com.\n@ IN NS ns2.example.com."

var dummyServer *server.Server
var resolverGenerator *resolver.Generator
var simpleHandler dns.Handler

func loadSimpleZone(zone string) dns.Handler {
	staticHandler := static.New(false)
	err := staticHandler.LoadZone(bytes.NewReader([]byte(zone)), "example.com.db", "example.com.", 300, false)
	if err != nil {
		panic(err)
	}

	return handler.New(nil, staticHandler, "example.com.", handler.Config{
		Authoritative: false,
	})
}

func initTests() {
	if dummyServer != nil {
		dummyServer.SetHandler(simpleHandler)
		resolverGenerator.FlushCache()
		resolverGenerator.CurrentTime = time.Now
		return
	}

	dummyServer = server.NewServer([]string{"127.0.0.1:12053"}, false)

	simpleHandler = loadSimpleZone(dummyZone)

	dummyServer.SetHandler(simpleHandler)
	go dummyServer.Serve()
	resolverGenerator = resolver.New([]*resolver.ServerConfig{
		{
			Addr:  "127.0.0.1:12053",
			Proto: "udp",
		},
	})
	dummyServer.WaitReady()
	err := resolverGenerator.Start()
	if err != nil {
		panic(err)
	}
}

func queryResolver(q dns.Question) *dns.Msg {
	initTests()

	answer, ns, _, rcode := resolverGenerator.HandleQuestion(&q, net.IPv4(127, 0, 0, 1))

	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Rcode: rcode,
		},
		Answer: answer,
		Ns:     ns,
	}
}
