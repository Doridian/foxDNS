package resolver

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type cacheEntry struct {
	msg    *dns.Msg
	time   time.Time
	expiry time.Time
	qtype  uint16
	qclass uint16
}

var (
	cacheResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "foxdns_resolver_cache_results",
		Help: "The number of cache hits/misses for DNS queries",
	}, []string{"result", "match_type"})

	cacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "foxdns_resolver_cache_size",
		Help: "The number of entries in the DNS cache",
	})

	cacheTTLHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "foxdns_resolver_cache_ttl",
		Help:    "TTLs for DNS cache entries",
		Buckets: []float64{1, 10, 60, 300, 600, 1800, 3600, 7200, 14400, 28800},
	})
)

func (r *Generator) SetCacheSize(size int) {
	r.cache.Resize(size)
}

func cacheKey(q *dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)
}

func cacheKeyDomain(q *dns.Question) string {
	return fmt.Sprintf("%s:ANY", q.Name)
}

func (r *Generator) getOrAddCache(q *dns.Question) (*dns.Msg, error) {
	key := cacheKey(q)
	keyDomain := cacheKeyDomain(q)

	entry, matchType := r.getFromCache(key, keyDomain, q)
	if entry != nil {
		cacheResults.WithLabelValues("hit", matchType).Inc()
		return entry, nil
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	defer wg.Done()
	cacheLock, loaded := r.cacheLock.LoadOrStore(key, wg)
	cacheLockWG := cacheLock.(*sync.WaitGroup)

	if loaded {
		cacheLockWG.Wait()

		entry, matchType := r.getFromCache(key, keyDomain, q)
		if entry != nil {
			cacheResults.WithLabelValues("wait", matchType).Inc()
			return entry, nil
		}
	} else {
		defer r.cacheLock.Delete(key)
	}

	reply, err := r.exchangeWithRetry(q)
	if err != nil {
		return nil, err
	}

	matchType = r.writeToCache(key, keyDomain, q, reply)
	cacheResults.WithLabelValues("miss", matchType).Inc()
	return reply, nil
}

func (r *Generator) cleanupCache() {
	now := time.Now()
	for _, key := range r.cache.Keys() {
		entry, ok := r.cache.Get(key)
		if ok && entry.expiry.Before(now) {
			r.cache.Remove(key)
		}
	}
	cacheSize.Set(float64(r.cache.Len()))
}

func (r *Generator) getFromCache(key string, keyDomain string, q *dns.Question) (*dns.Msg, string) {
	entry, ok := r.cache.Get(key)
	matchType := "exact"
	if !ok {
		entry, ok = r.cache.Get(keyDomain)
		if !ok {
			return nil, ""
		}
		if entry.qtype != q.Qtype || entry.qclass != q.Qclass {
			matchType = "domain"
		}
	}

	now := time.Now()
	if entry.expiry.Before(now) {
		return nil, ""
	}

	ttlAdjust := uint32(now.Sub(entry.time).Seconds())

	msg := entry.msg.Copy()

	if ttlAdjust > 1 {
		ttlAdjust--
		for _, rr := range msg.Answer {
			rrHdr := rr.Header()
			if rrHdr.Ttl < ttlAdjust {
				rrHdr.Ttl = 0
			} else {
				rrHdr.Ttl -= ttlAdjust
			}
		}
		for _, rr := range msg.Ns {
			rrHdr := rr.Header()
			if rrHdr.Ttl < ttlAdjust {
				rrHdr.Ttl = 0
			} else {
				rrHdr.Ttl -= ttlAdjust
			}
		}
	}

	return msg, matchType
}

func (r *Generator) writeToCache(key string, keyDomain string, q *dns.Question, m *dns.Msg) string {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return ""
	}

	minTTL := -1
	cacheTTL := -1
	authTTL := -1

	for _, rr := range m.Answer {
		ttl := int(rr.Header().Ttl)
		if cacheTTL < 0 || ttl < cacheTTL {
			cacheTTL = ttl
		}
	}

	for _, rr := range m.Ns {
		rrHdr := rr.Header()

		if rrHdr.Rrtype == dns.TypeSOA {
			minTTL = int(rr.(*dns.SOA).Minttl)
		}

		ttl := int(rrHdr.Ttl)
		if authTTL < 0 || ttl < authTTL {
			authTTL = ttl
		}
	}

	if cacheTTL < 0 {
		if authTTL >= 0 && authTTL < minTTL {
			cacheTTL = authTTL
		} else if minTTL >= 0 {
			cacheTTL = minTTL
		} else {
			cacheTTL = r.CacheNoReplyTTL
		}
	}

	if authTTL >= 0 && authTTL < cacheTTL {
		cacheTTL = authTTL
	}

	if cacheTTL > r.CacheMaxTTL {
		cacheTTL = r.CacheMaxTTL
	}

	if cacheTTL < r.CacheMinTTL {
		cacheTTL = r.CacheMinTTL
	}

	cacheTTLHistogram.Observe(float64(cacheTTL))

	if cacheTTL == 0 {
		return ""
	}

	now := time.Now()
	entry := &cacheEntry{
		time:   now,
		expiry: now.Add(time.Duration(cacheTTL) * time.Second),
		msg:    m,
		qtype:  q.Qtype,
		qclass: q.Qclass,
	}

	matchType := "exact"
	if m.Rcode == dns.RcodeNameError {
		key = keyDomain
		matchType = "domain"
	}
	r.cache.Add(key, entry)
	cacheSize.Set(float64(r.cache.Len()))
	return matchType
}
