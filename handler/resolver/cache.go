package resolver

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type cacheEntry struct {
	msg *dns.Msg

	time   time.Time
	expiry time.Time
	qtype  uint16
	qclass uint16
	hits   atomic.Uint64

	refreshTriggered bool
}

var ErrNoRefreshCacheDuringRefetch = fmt.Errorf("unnecessary to refresh cache during refetch")

var (
	cacheResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "foxdns_resolver_cache_results",
		Help: "The number of cache hits/misses for DNS queries",
	}, []string{"result", "match_type"})

	cacheStaleHits = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "foxdns_resolver_cache_stale_hits",
		Help:    "The number of cache hits for DNS queries that were stale",
		Buckets: []float64{1, 10, 30, 60, 120, 180, 240, 300, 360, 420, 480, 540, 600},
	})

	cacheStaleMisses = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "foxdns_resolver_cache_stale_misses",
		Help:    "The time since expiry of stale cache entries that were present but not usable",
		Buckets: []float64{1, 10, 30, 60, 120, 180, 240, 300, 360, 420, 480, 540, 600},
	})

	cacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "foxdns_resolver_cache_size",
		Help: "The number of entries in the DNS cache",
	})

	cacheTTLHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "foxdns_resolver_cache_ttl",
		Help:    "Upstream TTLs for DNS cache entries",
		Buckets: []float64{1, 10, 30, 60, 300, 600, 1800, 3600},
	})

	cacheHitsAtAgeOutHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "foxdns_resolver_cache_hits_at_age_out",
		Help:    "Number of cache hits for DNS cache entries at age out",
		Buckets: []float64{0, 1, 2, 3, 4, 5, 10, 20, 50, 100},
	})
)

func (g *Generator) SetCacheSize(size int) {
	g.cache.Resize(size)
}

func (g *Generator) FlushCache() {
	g.cache.Purge()
}

func cacheKey(q *dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)
}

func cacheKeyDomain(q *dns.Question) string {
	return fmt.Sprintf("%s:ANY", q.Name)
}

func (g *Generator) getOrAddCache(q *dns.Question, isCacheRefresh bool, incrementHits uint64) (string, string, *dns.Msg, error) {
	key := cacheKey(q)
	keyDomain := cacheKeyDomain(q)

	if !isCacheRefresh {
		msg, matchType := g.getFromCache(key, keyDomain, q, incrementHits)
		if msg != nil {
			return "hit", matchType, msg, nil
		}
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	defer wg.Done()
	cacheLock, loaded := g.cacheLock.LoadOrStore(key, wg)
	cacheLockWG := cacheLock.(*sync.WaitGroup)

	if loaded {
		if isCacheRefresh {
			return "", "", nil, ErrNoRefreshCacheDuringRefetch
		}

		cacheLockWG.Wait()

		msg, matchType := g.getFromCache(key, keyDomain, q, incrementHits)
		if msg != nil {
			return "wait", matchType, msg, nil
		}
	} else {
		defer g.cacheLock.Delete(key)
	}

	msg, err := g.exchangeWithRetry(q)
	if err != nil {
		return "", "", nil, err
	}

	matchType := g.processAndWriteToCache(key, keyDomain, q, msg, incrementHits)
	return "miss", matchType, msg, nil
}

func (g *Generator) cleanupCache() {
	minTime := g.CurrentTime().Add(-g.CacheStaleEntryKeepPeriod)

	toRemove := make([]string, 0)
	for _, key := range g.cache.Keys() {
		entry, ok := g.cache.Peek(key)
		if ok && entry.expiry.Before(minTime) {
			toRemove = append(toRemove, key)
		}
	}

	if len(toRemove) == 0 {
		return
	}

	g.cacheWriteLock.Lock()
	for _, key := range toRemove {
		entry, ok := g.cache.Peek(key)
		if ok && entry.expiry.Before(minTime) {
			g.cache.Remove(key)
			cacheHitsAtAgeOutHistogram.Observe(float64(entry.hits.Load()))
		}
	}
	g.cacheWriteLock.Unlock()

	cacheSize.Set(float64(g.cache.Len()))
}

func (g *Generator) countdownRecordTTL(rr dns.RR, ttlAdjust uint32) {
	rrHdr := rr.Header()

	if rrHdr.Ttl <= ttlAdjust {
		rrHdr.Ttl = 1
	} else {
		rrHdr.Ttl -= ttlAdjust
	}
}

func (g *Generator) adjustRecordTTL(rr dns.RR) (*dns.RR_Header, int) {
	rrHdr := rr.Header()
	origTtl := rrHdr.Ttl

	if rrHdr.Ttl < g.RecordMinTTL {
		rrHdr.Ttl = g.RecordMinTTL
	} else if rrHdr.Ttl > g.RecordMaxTTL {
		rrHdr.Ttl = g.RecordMaxTTL
	}

	return rrHdr, int(origTtl)
}

func (g *Generator) getFromCache(key string, keyDomain string, q *dns.Question, incrementHits uint64) (*dns.Msg, string) {
	entry, ok := g.cache.Get(key)
	matchType := "exact"
	if !ok {
		entry, ok = g.cache.Get(keyDomain)
		if !ok {
			return nil, ""
		}
		if entry.qtype != q.Qtype || entry.qclass != q.Qclass {
			matchType = "domain"
		}
	}

	now := g.CurrentTime()
	entryExpiresIn := entry.expiry.Sub(now)
	if entryExpiresIn <= -g.CacheReturnStalePeriod {
		timeSinceMiss := entryExpiresIn + g.CacheReturnStalePeriod
		cacheStaleMisses.Observe(float64(-timeSinceMiss.Seconds()))
		return nil, ""
	}

	if entryExpiresIn <= 0 {
		cacheStaleHits.Observe(float64(-entryExpiresIn.Seconds()))
	}

	entryHits := entry.hits.Add(incrementHits)

	if (entryExpiresIn <= 0 || (entryHits >= g.OpportunisticCacheMinHits && entryExpiresIn <= g.OpportunisticCacheMaxTimeLeft)) && !entry.refreshTriggered {
		entry.refreshTriggered = true
		go func() {
			_, _, _, _ = g.getOrAddCache(q, true, 0)
		}()
	}

	ttlAdjust := uint32(now.Sub(entry.time).Seconds())

	msg := entry.msg.Copy()

	if ttlAdjust > 0 {
		for _, rr := range msg.Answer {
			g.countdownRecordTTL(rr, ttlAdjust)
		}
		for _, rr := range msg.Ns {
			g.countdownRecordTTL(rr, ttlAdjust)
		}
	}

	return msg, matchType
}

func (g *Generator) processAndWriteToCache(key string, keyDomain string, q *dns.Question, m *dns.Msg, incrementHits uint64) string {
	minTTL := -1
	cacheTTL := -1
	authTTL := -1

	for _, rr := range m.Answer {
		_, ttl := g.adjustRecordTTL(rr)
		if cacheTTL < 0 || ttl < cacheTTL {
			cacheTTL = ttl
		}
	}

	for _, rr := range m.Ns {
		rrHdr, ttl := g.adjustRecordTTL(rr)

		if rrHdr.Rrtype == dns.TypeSOA {
			minTTL = int(rr.(*dns.SOA).Minttl)
		}

		if authTTL < 0 || ttl < authTTL {
			authTTL = ttl
		}
	}

	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return ""
	}

	if cacheTTL < 0 {
		if authTTL >= 0 && authTTL < minTTL {
			cacheTTL = authTTL
		} else if minTTL >= 0 {
			cacheTTL = minTTL
		} else {
			cacheTTL = g.CacheNoReplyTTL
		}
	}

	if authTTL >= 0 && authTTL < cacheTTL {
		cacheTTL = authTTL
	}

	cacheTTLHistogram.Observe(float64(cacheTTL))

	if cacheTTL > g.CacheMaxTTL {
		cacheTTL = g.CacheMaxTTL
	} else if cacheTTL < g.CacheMinTTL {
		cacheTTL = g.CacheMinTTL
	}

	if cacheTTL == 0 {
		return ""
	}

	now := g.CurrentTime()
	entry := &cacheEntry{
		time:   now,
		expiry: now.Add(time.Duration(cacheTTL) * time.Second),
		qtype:  q.Qtype,
		qclass: q.Qclass,
		msg:    m,
	}
	entry.hits.Store(incrementHits)

	matchType := "exact"
	if m.Rcode == dns.RcodeNameError {
		key = keyDomain
		matchType = "domain"
	}

	g.cacheWriteLock.Lock()
	g.cache.Add(key, entry)
	g.cacheWriteLock.Unlock()

	cacheSize.Set(float64(g.cache.Len()))
	return matchType
}
