package resolver

import (
	"container/list"
	"math"
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
	MaxIdleTime    time.Duration
	Retries        int
	RetryWait      time.Duration
	Timeout        time.Duration

	AllowOnlyFromPrivate bool

	connCond          *sync.Cond
	connections       int
	lastServerIdx     int
	freeConnections   *list.List
	connCleanupTicker *time.Ticker

	CacheMaxTTL     int
	CacheMinTTL     int
	CacheNoReplyTTL int

	RecordMinTTL uint32
	RecordMaxTTL uint32

	cache              *lru.Cache[string, *cacheEntry]
	cacheLock          *sync.Map
	cacheCleanupTicker *time.Ticker
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
		MaxIdleTime:          time.Second * 15,
		Retries:              3,
		AllowOnlyFromPrivate: true,
		RetryWait:            time.Second,

		CacheMaxTTL:     3600,
		CacheMinTTL:     0,
		CacheNoReplyTTL: 30,

		RecordMinTTL: 0,
		RecordMaxTTL: math.MaxUint32,

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
	err := r.Stop()
	if err != nil {
		return err
	}

	cacheCleanupTicker := time.NewTicker(time.Minute)
	r.cacheCleanupTicker = cacheCleanupTicker
	go func() {
		for {
			_, ok := <-cacheCleanupTicker.C
			if !ok {
				return
			}
			r.cleanupCache()
		}
	}()

	connCleanupTicker := time.NewTicker(r.MaxIdleTime / 2)
	r.connCleanupTicker = connCleanupTicker
	go func() {
		for {
			_, ok := <-connCleanupTicker.C
			if !ok {
				return
			}
			r.cleanupConns()
		}
	}()

	return nil
}

func (r *Generator) Stop() error {
	if r.cacheCleanupTicker != nil {
		r.cacheCleanupTicker.Stop()
		r.cacheCleanupTicker = nil
	}
	if r.connCleanupTicker != nil {
		r.connCleanupTicker.Stop()
		r.connCleanupTicker = nil
	}
	return nil
}

func (r *Generator) GetName() string {
	return "resolver"
}
