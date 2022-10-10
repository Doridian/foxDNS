package resolver

import (
	"container/list"
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
	lastServerIdx   int
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
