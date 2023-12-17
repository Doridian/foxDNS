package resolver

import (
	"container/list"
	"sync"
	"time"

	"github.com/FoxDenHome/foxdns/util"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

type Generator struct {
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

	cache     *lru.Cache[string, *cacheEntry]
	cacheLock *sync.Map
}

var _ dns.Handler = &Generator{}

func New(servers []string) *Generator {
	cache, _ := lru.New[string, *cacheEntry](4096)

	return &Generator{
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

		cache:     cache,
		cacheLock: &sync.Map{},
	}
}

func (r *Generator) SetTimeout(timeout time.Duration) {
	r.Client.ReadTimeout = timeout
	r.Client.WriteTimeout = timeout
}

func (r *Generator) Refresh() error {
	return nil
}

func (r *Generator) Start() error {
	return nil
}

func (r *Generator) Stop() error {
	return nil
}
