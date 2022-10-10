package main

import (
	"github.com/FoxDenHome/foxdns/authority"
	"github.com/FoxDenHome/foxdns/rdns"
	"github.com/FoxDenHome/foxdns/resolver"
	"github.com/FoxDenHome/foxdns/server"
)

func main() {
	rdnsv6 := &rdns.RDNSv6Generator{
		PTRSuffix: "ip6.foxden.network",
	}
	authv6 := authority.NewAuthorityHandler([]string{
		rdnsv6.PTRSuffix,
		"9.6.0.f.4.4.d.7.e.0.a.2.ip6.arpa",
		"a.c.1.2.2.0.f.8.e.0.a.2.ip6.arpa",
	}, []string{
		"ns-int.foxden.network.",
	}, "internal.foxden.network.")
	authv6.Child = rdnsv6

	rdnsv4 := &rdns.RDNSv4Generator{
		PTRSuffix: "ip4.foxden.network",
	}
	authv4 := authority.NewAuthorityHandler([]string{
		rdnsv4.PTRSuffix,
		"10.in-addr.arpa",
	}, []string{
		"ns-int.foxden.network.",
	}, "internal.foxden.network.")
	authv4.Child = rdnsv4

	resolv := resolver.NewResolver([]string{
		"8.8.8.8:53",
	})
	s := server.NewServer()
	authv6.Register(s.Mux)
	authv4.Register(s.Mux)
	s.Mux.Handle(".", resolv)
	s.Serve()
}
