package resolver

import (
	"container/list"
	"sync"
	"time"

	"github.com/FoxDenHome/foxdns/util"
	lru "github.com/hashicorp/golang-lru"
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

	cache *lru.Cache
}

var _ dns.Handler = &Resolver{}

func NewResolver(servers []string) *Resolver {
	cache, _ := lru.New(4096)

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

		cache: cache,
	}
}

func (r *Resolver) SetTimeout(timeout time.Duration) {
	r.Client.ReadTimeout = timeout
	r.Client.WriteTimeout = timeout
}
