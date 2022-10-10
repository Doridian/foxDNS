package server

import (
	"log"
	"sync"

	"github.com/FoxDenHome/foxdns/resolver"
	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type Server struct {
	Resolver   *resolver.Resolver
	Mux        *dns.ServeMux
	ListenAddr string

	serveWait sync.WaitGroup
}

func NewServer() *Server {
	return &Server{
		Mux:        dns.NewServeMux(),
		ListenAddr: ":8053",
	}
}

func (s *Server) Serve() {
	s.serveWait.Add(1)
	go s.serve("tcp")

	s.serveWait.Add(1)
	go s.serve("udp")

	s.serveWait.Wait()
}

func (s *Server) serve(net string) {
	defer s.serveWait.Done()

	dnsServer := &dns.Server{
		Addr:         s.ListenAddr,
		Net:          net,
		Handler:      s.Mux,
		UDPSize:      util.DNSMaxSize,
		ReadTimeout:  util.DefaultTimeout,
		WriteTimeout: util.DefaultTimeout,
	}

	log.Printf("Lisrening on %s net %s", s.ListenAddr, net)
	err := dnsServer.ListenAndServe()
	if err != nil {
		log.Printf("Error listening on %s net %s: %v", s.ListenAddr, net, err)
	}
}
