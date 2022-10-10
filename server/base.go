package server

import (
	"log"
	"sync"

	"github.com/FoxDenHome/foxdns/resolver"
	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type Server struct {
	Resolver *resolver.Resolver
	Mux      *dns.ServeMux
	Listen   []string

	serveWait sync.WaitGroup
}

func NewServer() *Server {
	return &Server{
		Mux:    dns.NewServeMux(),
		Listen: []string{":8053"},
	}
}

func (s *Server) Serve() {
	for _, listen := range s.Listen {
		s.serveWait.Add(1)
		go s.serve("tcp", listen)

		s.serveWait.Add(1)
		go s.serve("udp", listen)
	}

	s.serveWait.Wait()
}

func (s *Server) serve(net string, addr string) {
	defer s.serveWait.Done()

	dnsServer := &dns.Server{
		Addr:         addr,
		Net:          net,
		Handler:      s.Mux,
		UDPSize:      util.DNSMaxSize,
		ReadTimeout:  util.DefaultTimeout,
		WriteTimeout: util.DefaultTimeout,
	}

	log.Printf("Listening on %s net %s", addr, net)
	err := dnsServer.ListenAndServe()
	if err != nil {
		log.Printf("Error listening on %s net %s: %v", addr, net, err)
	}
}
