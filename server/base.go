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
	initWait  sync.WaitGroup
}

func NewServer() *Server {
	return &Server{
		Mux:    dns.NewServeMux(),
		Listen: []string{":8053"},
	}
}

func (s *Server) Serve() {
	for _, listen := range s.Listen {
		s.initWait.Add(1)
		s.serveWait.Add(1)
		go s.serve("tcp", listen)

		s.initWait.Add(1)
		s.serveWait.Add(1)
		go s.serve("udp", listen)
	}

	s.initWait.Wait()
	dropPrivs()

	log.Printf("Server fully initialized!")

	s.serveWait.Wait()
}

func (s *Server) serve(net string, addr string) {
	defer s.serveWait.Done()
	initWaitSet := false

	initWaitDone := func() {
		if initWaitSet {
			return
		}
		initWaitSet = true
		s.initWait.Done()
	}
	defer initWaitDone()

	dnsServer := &dns.Server{
		Addr:         addr,
		Net:          net,
		Handler:      s.Mux,
		UDPSize:      util.DNSMaxSize,
		ReadTimeout:  util.DefaultTimeout,
		WriteTimeout: util.DefaultTimeout,
		NotifyStartedFunc: func() {
			log.Printf("Listening on %s net %s", addr, net)
			initWaitDone()
		},
	}

	err := dnsServer.ListenAndServe()
	if err != nil {
		log.Printf("Error listening on %s net %s: %v", addr, net, err)
	}
}
