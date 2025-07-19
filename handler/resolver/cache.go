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

func (h *Handler) SetCacheSize(size int) {
	h.cache.Resize(size)
}

func (h *Handler) FlushCache() {
	h.cache.Purge()
}

func cacheKey(q *dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)
}

func cacheKeyDomain(q *dns.Question) string {
	return fmt.Sprintf("%s:ANY", q.Name)
}

func (h *Handler) getOrAddCache(q *dns.Question, isCacheRefresh bool, incrementHits uint64) (string, string, *dns.Msg, error) {
	key := cacheKey(q)
	keyDomain := cacheKeyDomain(q)

	if !isCacheRefresh {
		msg, matchType := h.getFromCache(key, keyDomain, q, incrementHits)
		if msg != nil {
			return "hit", matchType, msg, nil
		}
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	defer wg.Done()
	cacheLock, loaded := h.cacheLock.LoadOrStore(key, wg)
	cacheLockWG := cacheLock.(*sync.WaitGroup)

	if loaded {
		if isCacheRefresh {
			return "", "", nil, ErrNoRefreshCacheDuringRefetch
		}

		cacheLockWG.Wait()

		msg, matchType := h.getFromCache(key, keyDomain, q, incrementHits)
		if msg != nil {
			return "wait", matchType, msg, nil
		}
	} else {
		defer h.cacheLock.Delete(key)
	}

	msg, err := h.exchangeWithRetry(q)
	if err != nil {
		return "", "", nil, err
	}

	matchType := h.processAndWriteToCache(key, keyDomain, q, msg, incrementHits)
	return "miss", matchType, msg, nil
}

func (h *Handler) cleanupCache() {
	minTime := h.CurrentTime().Add(-h.CacheStaleEntryKeepPeriod)

	toRemove := make([]string, 0)
	for _, key := range h.cache.Keys() {
		entry, ok := h.cache.Peek(key)
		if ok && entry.expiry.Before(minTime) {
			toRemove = append(toRemove, key)
		}
	}

	if len(toRemove) == 0 {
		return
	}

	h.cacheWriteLock.Lock()
	for _, key := range toRemove {
		entry, ok := h.cache.Peek(key)
		if ok && entry.expiry.Before(minTime) {
			h.cache.Remove(key)
			cacheHitsAtAgeOutHistogram.Observe(float64(entry.hits.Load()))
		}
	}
	h.cacheWriteLock.Unlock()

	cacheSize.Set(float64(h.cache.Len()))
}

func (h *Handler) countdownRecordTTL(rr dns.RR, ttlAdjust uint32) {
	rrHdr := rr.Header()

	if rrHdr.Ttl <= ttlAdjust {
		rrHdr.Ttl = 1
	} else {
		rrHdr.Ttl -= ttlAdjust
	}
}

func (h *Handler) adjustRecordTTL(rr dns.RR) (*dns.RR_Header, int) {
	rrHdr := rr.Header()
	origTtl := rrHdr.Ttl

	if rrHdr.Ttl < h.RecordMinTTL {
		rrHdr.Ttl = h.RecordMinTTL
	} else if rrHdr.Ttl > h.RecordMaxTTL {
		rrHdr.Ttl = h.RecordMaxTTL
	}

	return rrHdr, int(origTtl)
}

func (h *Handler) getFromCache(key string, keyDomain string, q *dns.Question, incrementHits uint64) (*dns.Msg, string) {
	entry, ok := h.cache.Get(key)
	matchType := "exact"
	if !ok {
		entry, ok = h.cache.Get(keyDomain)
		if !ok {
			return nil, ""
		}
		if entry.qtype != q.Qtype || entry.qclass != q.Qclass {
			matchType = "domain"
		}
	}

	now := h.CurrentTime()
	entryExpiresIn := entry.expiry.Sub(now)
	if entryExpiresIn <= -h.CacheReturnStalePeriod {
		timeSinceMiss := entryExpiresIn + h.CacheReturnStalePeriod
		cacheStaleMisses.Observe(float64(-timeSinceMiss.Seconds()))
		return nil, ""
	}

	if entryExpiresIn <= 0 {
		cacheStaleHits.Observe(float64(-entryExpiresIn.Seconds()))
	}

	entryHits := entry.hits.Add(incrementHits)

	if (entryExpiresIn <= 0 || (entryHits >= h.OpportunisticCacheMinHits && entryExpiresIn <= h.OpportunisticCacheMaxTimeLeft)) && !entry.refreshTriggered {
		entry.refreshTriggered = true
		go func() {
			_, _, _, _ = h.getOrAddCache(q, true, 0)
		}()
	}

	ttlAdjust := uint32(now.Sub(entry.time).Seconds())

	msg := entry.msg.Copy()

	if ttlAdjust > 0 {
		for _, rr := range msg.Answer {
			h.countdownRecordTTL(rr, ttlAdjust)
		}
		for _, rr := range msg.Ns {
			h.countdownRecordTTL(rr, ttlAdjust)
		}
	}

	return msg, matchType
}

func (h *Handler) processAndWriteToCache(key string, keyDomain string, q *dns.Question, m *dns.Msg, incrementHits uint64) string {
	minTTL := -1
	cacheTTL := -1
	authTTL := -1

	for _, rr := range m.Answer {
		_, ttl := h.adjustRecordTTL(rr)
		if cacheTTL < 0 || ttl < cacheTTL {
			cacheTTL = ttl
		}
	}

	for _, rr := range m.Ns {
		rrHdr, ttl := h.adjustRecordTTL(rr)

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
			cacheTTL = h.CacheNoReplyTTL
		}
	}

	if authTTL >= 0 && authTTL < cacheTTL {
		cacheTTL = authTTL
	}

	cacheTTLHistogram.Observe(float64(cacheTTL))

	if cacheTTL > h.CacheMaxTTL {
		cacheTTL = h.CacheMaxTTL
	} else if cacheTTL < h.CacheMinTTL {
		cacheTTL = h.CacheMinTTL
	}

	if cacheTTL == 0 {
		return ""
	}

	now := h.CurrentTime()
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

	h.cacheWriteLock.Lock()
	h.cache.Add(key, entry)
	h.cacheWriteLock.Unlock()

	cacheSize.Set(float64(h.cache.Len()))
	return matchType
}
