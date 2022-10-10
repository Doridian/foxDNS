package resolver

import (
	"container/list"
	"log"
	"sync"
	"time"

	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type Resolver struct {
	Servers []string
	Client  *dns.Client

	MaxConnections int
	Retries        int
	RetryWait      time.Duration
	Timeout        time.Duration

	AllowOnlyFromPrivate bool

	connCond        *sync.Cond
	connections     int
	freeConnections *list.List
}

var _ dns.Handler = &Resolver{}

func NewResolver(servers []string) *Resolver {
	return &Resolver{
		Servers: servers,
		Client: &dns.Client{
			Net:          "udp",
			ReadTimeout:  util.DefaultTimeout,
			WriteTimeout: util.DefaultTimeout,
		},
		MaxConnections:       10,
		Retries:              3,
		AllowOnlyFromPrivate: true,
		RetryWait:            time.Second,

		connCond:        sync.NewCond(&sync.Mutex{}),
		connections:     0,
		freeConnections: list.New(),
	}
}

func (r *Resolver) SetTimeout(timeout time.Duration) {
	r.Client.ReadTimeout = timeout
	r.Client.WriteTimeout = timeout
}

func (r *Resolver) acquireConn() (conn *dns.Conn, err error) {
	r.connCond.L.Lock()

	for {
		firstElem := r.freeConnections.Front()
		if firstElem != nil {
			conn = r.freeConnections.Remove(firstElem).(*dns.Conn)
			r.connCond.L.Unlock()
			return
		}

		if r.connections < r.MaxConnections {
			r.connections++
			srv := r.Servers[0]
			r.connCond.L.Unlock()
			conn, err = r.Client.Dial(srv)
			return
		}

		r.connCond.Wait()
	}
}

func (r *Resolver) returnConn(conn *dns.Conn, err error) {
	r.connCond.L.Lock()
	defer r.connCond.L.Unlock()

	if err == nil {
		r.freeConnections.PushBack(conn)
	} else {
		r.connections--
	}

	r.connCond.Signal()
}

func (r *Resolver) exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	var conn *dns.Conn
	conn, err = r.acquireConn()
	if err != nil {
		r.returnConn(conn, err)
		return
	}

	resp, _, err = r.Client.ExchangeWithConn(m, conn)
	r.returnConn(conn, err)
	return
}

func (r *Resolver) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	util.SetEDNS0(m)

	for i := r.Retries; i > 0; i-- {
		resp, err = r.exchange(m)
		if err == nil {
			return
		}
		time.Sleep(r.RetryWait)
	}
	return
}

func (r *Resolver) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetRcode(msg, dns.RcodeServerFailure)
	util.SetEDNS0(reply)
	defer wr.WriteMsg(reply)

	if r.AllowOnlyFromPrivate {
		ip := util.ExtractIP(wr.RemoteAddr())
		if !util.IPIsPrivateOrLocal(ip) {
			reply.RecursionAvailable = false
			reply.Rcode = dns.RcodeRefused
			return
		}
	}

	recursionReply, err := r.Exchange(msg)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}

	reply.Rcode = recursionReply.Rcode
	reply.Answer = recursionReply.Answer
	reply.Extra = recursionReply.Extra
}
