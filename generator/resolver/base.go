package resolver

import (
	"container/list"
	"crypto/tls"
	"math"
	"sync"
	"time"

	"github.com/Doridian/foxDNS/generator"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

type ServerConfig struct {
	Addr               string
	Proto              string
	ServerName         string
	RequireCookie      bool
	MaxParallelQueries int
	client             *dns.Client
	Timeout            time.Duration

	freeQuerySlots  *list.List
	querySlotCond   *sync.Cond
	inFlightQueries int
}

type ServerStrategy int

const (
	StrategyRoundRobin ServerStrategy = iota
	StrategyRandom
	StrategyFailover
)

type Generator struct {
	ServerStrategy ServerStrategy
	Servers        []*ServerConfig

	lastServerIdx int
	MaxIdleTime   time.Duration
	Attempts      int
	RetryWait     time.Duration
	LogFailures   bool

	connCleanupTicker *time.Ticker
	shouldPadLen      int

	CacheMaxTTL               int
	CacheMinTTL               int
	CacheNoReplyTTL           int
	CacheStaleEntryKeepPeriod time.Duration
	CacheReturnStalePeriod    time.Duration

	CurrentTime func() time.Time

	RecordMinTTL uint32
	RecordMaxTTL uint32

	OpportunisticCacheMinHits     uint64
	OpportunisticCacheMaxTimeLeft time.Duration

	cache              *lru.Cache[string, *cacheEntry]
	cacheLock          *sync.Map
	cacheWriteLock     sync.Mutex
	cacheCleanupTicker *time.Ticker
}

var _ generator.Generator = &Generator{}

func New(servers []*ServerConfig) *Generator {
	cache, _ := lru.New[string, *cacheEntry](4096)

	gen := &Generator{
		ServerStrategy: StrategyRoundRobin,
		Servers:        servers,
		MaxIdleTime:    time.Second * 15,
		Attempts:       3,
		RetryWait:      time.Millisecond * 100,
		LogFailures:    false,

		CacheMaxTTL:               3600,
		CacheMinTTL:               0,
		CacheNoReplyTTL:           30,
		CacheStaleEntryKeepPeriod: time.Second * 15,
		CacheReturnStalePeriod:    0,

		CurrentTime: time.Now,

		RecordMinTTL: 0,
		RecordMaxTTL: math.MaxUint32,

		shouldPadLen: 0,

		OpportunisticCacheMinHits:     math.MaxUint64,
		OpportunisticCacheMaxTimeLeft: 0,

		cache:     cache,
		cacheLock: &sync.Map{},
	}

	for _, srv := range gen.Servers {
		srv.client = &dns.Client{
			Net:          srv.Proto,
			Timeout:      srv.Timeout,
			DialTimeout:  srv.Timeout,
			ReadTimeout:  srv.Timeout,
			WriteTimeout: srv.Timeout,
		}
		srv.freeQuerySlots = list.New()
		srv.querySlotCond = sync.NewCond(&sync.Mutex{})
		srv.inFlightQueries = 0
		if srv.MaxParallelQueries <= 0 {
			srv.MaxParallelQueries = 10
		}

		if srv.Proto == "tcp-tls" {
			gen.shouldPadLen = 128
		}

		if srv.ServerName != "" {
			srv.client.TLSConfig = &tls.Config{
				ServerName: srv.ServerName,
			}
		}
	}

	return gen
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
			r.cleanupAllQuerySlots()
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
