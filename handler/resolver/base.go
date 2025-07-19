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

type Handler struct {
	ServerStrategy ServerStrategy
	Servers        []*ServerConfig

	lastServerIdx int
	MaxIdleTime   time.Duration
	Attempts      int
	RetryWait     time.Duration
	LogFailures   bool

	connCleanupTicker *time.Ticker
	shouldPadLen      int

	RequireCookie bool

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

func New(servers []*ServerConfig) *Handler {
	cache, _ := lru.New[string, *cacheEntry](4096)

	gen := &Handler{
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

func (h *Handler) Refresh() error {
	return nil
}

func (h *Handler) Start() error {
	err := h.Stop()
	if err != nil {
		return err
	}

	cacheCleanupTicker := time.NewTicker(time.Minute)
	h.cacheCleanupTicker = cacheCleanupTicker
	go func() {
		for {
			_, ok := <-cacheCleanupTicker.C
			if !ok {
				return
			}
			h.cleanupCache()
		}
	}()

	connCleanupTicker := time.NewTicker(h.MaxIdleTime / 2)
	h.connCleanupTicker = connCleanupTicker
	go func() {
		for {
			_, ok := <-connCleanupTicker.C
			if !ok {
				return
			}
			h.cleanupAllQuerySlots()
		}
	}()

	return nil
}

func (h *Handler) Stop() error {
	if h.cacheCleanupTicker != nil {
		h.cacheCleanupTicker.Stop()
		h.cacheCleanupTicker = nil
	}
	if h.connCleanupTicker != nil {
		h.connCleanupTicker.Stop()
		h.connCleanupTicker = nil
	}
	return nil
}

func (h *Handler) GetName() string {
	return "resolver"
}
