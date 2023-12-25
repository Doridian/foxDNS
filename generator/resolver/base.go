package resolver

import (
	"container/list"
	"crypto/tls"
	"math"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

type ServerConfig struct {
	Addr       string
	Proto      string
	ServerName string
	client     *dns.Client
}

type Generator struct {
	Servers []*ServerConfig

	MaxConnections int
	MaxIdleTime    time.Duration
	Retries        int
	RetryWait      time.Duration

	AllowOnlyFromPrivate bool

	connCond          *sync.Cond
	connections       int
	lastServerIdx     int
	freeConnections   *list.List
	connCleanupTicker *time.Ticker

	CacheMaxTTL               int
	CacheMinTTL               int
	CacheNoReplyTTL           int
	CacheStaleEntryKeepPeriod time.Duration

	RecordMinTTL uint32
	RecordMaxTTL uint32

	OpportunisticCacheMinHits     uint64
	OpportunisticCacheMaxTimeLeft time.Duration

	cache              *lru.Cache[string, *cacheEntry]
	cacheLock          *sync.Map
	cacheCleanupTicker *time.Ticker
}

var _ dns.Handler = &Generator{}

func New(servers []*ServerConfig) *Generator {
	cache, _ := lru.New[string, *cacheEntry](4096)

	gen := &Generator{
		Servers:              servers,
		MaxConnections:       10,
		MaxIdleTime:          time.Second * 15,
		Retries:              3,
		AllowOnlyFromPrivate: true,
		RetryWait:            time.Second,

		CacheMaxTTL:               3600,
		CacheMinTTL:               0,
		CacheNoReplyTTL:           30,
		CacheStaleEntryKeepPeriod: time.Second * 15,

		RecordMinTTL: 0,
		RecordMaxTTL: math.MaxUint32,

		connCond:        sync.NewCond(&sync.Mutex{}),
		connections:     0,
		freeConnections: list.New(),

		OpportunisticCacheMinHits:     math.MaxUint64,
		OpportunisticCacheMaxTimeLeft: 0,

		cache:     cache,
		cacheLock: &sync.Map{},
	}

	for _, srv := range gen.Servers {
		srv.client = &dns.Client{
			Net: srv.Proto,
		}

		if srv.ServerName != "" {
			srv.client.TLSConfig = &tls.Config{
				ServerName: srv.ServerName,
			}
		}
	}

	return gen
}

func (r *Generator) SetTimeout(timeout time.Duration) {
	for _, srv := range r.Servers {
		srv.client.Timeout = timeout
		srv.client.DialTimeout = timeout
		srv.client.ReadTimeout = timeout
		srv.client.WriteTimeout = timeout
	}
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
