package server

import (
	"log"
	"sync"

	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type Server struct {
	listen []string

	handler dns.Handler

	serveWait sync.WaitGroup
	initWait  sync.WaitGroup

	serverLock sync.Mutex
	servers    map[*dns.Server]bool
}

func NewServer(listen []string) *Server {
	return &Server{
		listen:  listen,
		servers: make(map[*dns.Server]bool),
	}
}

func (s *Server) SetHandler(handler dns.Handler) {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	s.handler = handler
	for server := range s.servers {
		server.Handler = handler
	}
}

func (s *Server) Serve() {
	for _, listen := range s.listen {
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

const QRBit = 1 << 15

func msgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	if isResponse := dh.Bits&QRBit != 0; isResponse {
		return dns.MsgIgnore
	}

	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeQuery {
		return dns.MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 || dh.Ancount > 0 || dh.Nscount > 0 || dh.Arcount > 0 {
		return dns.MsgReject
	}

	return dns.MsgAccept
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

	s.serverLock.Lock()
	dnsServer := &dns.Server{
		Addr:          addr,
		Net:           net,
		Handler:       s.handler,
		UDPSize:       util.DNSMaxSize,
		ReadTimeout:   util.DefaultTimeout,
		WriteTimeout:  util.DefaultTimeout,
		MsgAcceptFunc: msgAcceptFunc,
		NotifyStartedFunc: func() {
			log.Printf("Listening on %s net %s", addr, net)
			initWaitDone()
		},
	}
	s.servers[dnsServer] = true
	s.serverLock.Unlock()

	defer func() {
		s.serverLock.Lock()
		delete(s.servers, dnsServer)
		s.serverLock.Unlock()
	}()

	err := dnsServer.ListenAndServe()
	if err != nil {
		log.Printf("Error listening on %s net %s: %v", addr, net, err)
	}
}
