package server

import (
	"log"
	"sync"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type Server struct {
	listen []string

	handler     dns.Handler
	handlerLock sync.RWMutex

	serveWait      sync.WaitGroup
	initWait       sync.WaitGroup
	privDropWait   sync.WaitGroup
	enablePrivDrop bool

	serverLock sync.Mutex
	servers    map[*dns.Server]bool
}

func NewServer(listen []string, enablePrivDrop bool) *Server {
	return &Server{
		listen:         listen,
		servers:        make(map[*dns.Server]bool),
		enablePrivDrop: enablePrivDrop,
	}
}

func (s *Server) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	s.handlerLock.RLock()
	handler := s.handler
	s.handlerLock.RUnlock()
	handler.ServeDNS(wr, msg)
}

func (s *Server) SetHandler(handler dns.Handler) {
	s.handlerLock.Lock()
	defer s.handlerLock.Unlock()
	s.handler = handler
}

func (s *Server) WaitReady() {
	s.initWait.Wait()
	s.privDropWait.Wait()
}

func (s *Server) Serve() {
	s.privDropWait.Add(1)

	for _, listen := range s.listen {
		s.initWait.Add(1)
		s.serveWait.Add(1)
		go s.serve("tcp", listen)

		s.initWait.Add(1)
		s.serveWait.Add(1)
		go s.serve("udp", listen)
	}

	s.initWait.Wait()
	if s.enablePrivDrop {
		dropPrivs()
	}
	s.privDropWait.Done()

	log.Printf("Server fully initialized!")

	s.serveWait.Wait()
}

const QRBit = 1 << 15

func msgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	if dh.Bits&QRBit != 0 { // is response
		return dns.MsgIgnore
	}

	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeQuery {
		return dns.MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 || dh.Ancount > 0 || dh.Nscount > 0 || dh.Arcount > 2 {
		return dns.MsgReject
	}

	return dns.MsgAccept
}

func (s *Server) serve(net string, addr string) {
	defer s.serveWait.Done()
	initWaitSync := sync.Mutex{}
	initWaitSet := false

	initWaitDone := func() {
		initWaitSync.Lock()
		defer initWaitSync.Unlock()
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
		Handler:       s,
		UDPSize:       int(util.UDPSize),
		ReadTimeout:   util.DefaultTimeout,
		WriteTimeout:  util.DefaultTimeout,
		MsgAcceptFunc: msgAcceptFunc,
		NotifyStartedFunc: func() {
			log.Printf("Listening on %s net %s", addr, net)
			initWaitDone()
			s.privDropWait.Wait()
			log.Printf("Handling requests on %s net %s", addr, net)
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

func (s *Server) Shutdown() {
	s.serverLock.Lock()
	for dnsServer := range s.servers {
		_ = dnsServer.Shutdown()
	}
	s.servers = make(map[*dns.Server]bool)
	s.serverLock.Unlock()
}
