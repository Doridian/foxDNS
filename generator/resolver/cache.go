package resolver

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type cacheEntry struct {
	msg   *dns.Msg
	edns0 *dns.OPT

	time   time.Time
	expiry time.Time
	qtype  uint16
	qclass uint16
	hits   atomic.Uint64

	refreshTriggered bool
}

var (
	cacheResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "foxdns_resolver_cache_results",
		Help: "The number of cache hits/misses for DNS queries",
	}, []string{"result", "match_type"})

	cacheStaleHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "foxdns_resolver_cache_stale_hits",
		Help: "The number of cache hits for DNS queries that were stale",
	})

	cacheStaleReturns = promauto.NewCounter(prometheus.CounterOpts{
		Name: "foxdns_resolver_cache_stale_returns",
		Help: "The number of cache hits for DNS queries that were stale but got returned to the client",
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
		Buckets: []float64{1, 2, 3, 4, 5, 10, 20, 50, 100},
	})
)

func (r *Generator) SetCacheSize(size int) {
	r.cache.Resize(size)
}

func (r *Generator) FlushCache() {
	r.cache.Purge()
}

func cacheKey(q *dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)
}

func cacheKeyDomain(q *dns.Question) string {
	return fmt.Sprintf("%s:ANY", q.Name)
}

func (r *Generator) getOrAddCache(q *dns.Question, forceRequery bool) (*dns.Msg, *dns.OPT, error) {
	key := cacheKey(q)
	keyDomain := cacheKeyDomain(q)

	if !forceRequery {
		msg, edns0, matchType := r.getFromCache(key, keyDomain, q)
		if msg != nil {
			cacheResults.WithLabelValues("hit", matchType).Inc()
			return msg, edns0, nil
		}
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	defer wg.Done()
	cacheLock, loaded := r.cacheLock.LoadOrStore(key, wg)
	cacheLockWG := cacheLock.(*sync.WaitGroup)

	if loaded {
		if forceRequery {
			return nil, nil, nil
		}

		cacheLockWG.Wait()

		entry, edns0, matchType := r.getFromCache(key, keyDomain, q)
		if entry != nil {
			// Can't be  hit when forceRequery is true
			cacheResults.WithLabelValues("wait", matchType).Inc()
			return entry, edns0, nil
		}
	} else {
		defer r.cacheLock.Delete(key)
	}

	reply, err := r.exchangeWithRetry(q)
	if err != nil {
		return nil, nil, err
	}

	edns0, matchType := r.processAndWriteToCache(key, keyDomain, q, reply)
	if !forceRequery {
		cacheResults.WithLabelValues("miss", matchType).Inc()
	}
	return reply, edns0, nil
}

func (r *Generator) cleanupCache() {
	minTime := time.Now().Add(-r.CacheStaleEntryKeepPeriod)
	for _, key := range r.cache.Keys() {
		entry, ok := r.cache.Get(key)
		if ok && entry.expiry.Before(minTime) {
			r.cache.Remove(key)
			cacheHitsAtAgeOutHistogram.Observe(float64(entry.hits.Load()))
		}
	}
	cacheSize.Set(float64(r.cache.Len()))
}

func (r *Generator) countdownRecordTTL(rr dns.RR, ttlAdjust uint32) {
	rrHdr := rr.Header()

	if rrHdr.Ttl <= ttlAdjust {
		rrHdr.Ttl = 1
	} else {
		rrHdr.Ttl -= ttlAdjust
	}
}

func (r *Generator) adjustRecordTTL(rr dns.RR) (*dns.RR_Header, int) {
	rrHdr := rr.Header()
	origTtl := rrHdr.Ttl

	if rrHdr.Ttl < r.RecordMinTTL {
		rrHdr.Ttl = r.RecordMinTTL
	} else if rrHdr.Ttl > r.RecordMaxTTL {
		rrHdr.Ttl = r.RecordMaxTTL
	}

	return rrHdr, int(origTtl)
}

func (r *Generator) getFromCache(key string, keyDomain string, q *dns.Question) (*dns.Msg, *dns.OPT, string) {
	entry, ok := r.cache.Get(key)
	matchType := "exact"
	if !ok {
		entry, ok = r.cache.Get(keyDomain)
		if !ok {
			return nil, nil, ""
		}
		if entry.qtype != q.Qtype || entry.qclass != q.Qclass {
			matchType = "domain"
		}
	}

	now := time.Now()
	entryExpiresIn := entry.expiry.Sub(now)
	if entryExpiresIn <= -r.CacheReturnStalePeriod {
		cacheStaleHits.Inc()
		return nil, nil, ""
	}

	if entryExpiresIn <= 0 {
		cacheStaleReturns.Inc()
	}

	entryHits := entry.hits.Add(1)

	if (entryExpiresIn <= 0 || (entryHits >= r.OpportunisticCacheMinHits && entryExpiresIn <= r.OpportunisticCacheMaxTimeLeft)) && !entry.refreshTriggered {
		entry.refreshTriggered = true
		go func() {
			_, _, _ = r.getOrAddCache(q, true)
		}()
	}

	ttlAdjust := uint32(now.Sub(entry.time).Seconds())

	msg := entry.msg.Copy()

	if ttlAdjust > 0 {
		for _, rr := range msg.Answer {
			r.countdownRecordTTL(rr, ttlAdjust)
		}
		for _, rr := range msg.Ns {
			r.countdownRecordTTL(rr, ttlAdjust)
		}
	}

	return msg, entry.edns0, matchType
}

func (r *Generator) processAndWriteToCache(key string, keyDomain string, q *dns.Question, m *dns.Msg) (*dns.OPT, string) {
	minTTL := -1
	cacheTTL := -1
	authTTL := -1

	edns0Index := -1
	edns0 := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	edns0.SetUDPSize(util.UDPSize)

	for idx, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			continue
		}

		edns0Index = idx
		edns0.Hdr.Ttl = rr.Header().Ttl
		break
	}

	if edns0Index >= 0 {
		m.Extra = append(m.Extra[:edns0Index], m.Extra[edns0Index+1:]...)
	}

	for _, rr := range m.Answer {
		_, ttl := r.adjustRecordTTL(rr)
		if cacheTTL < 0 || ttl < cacheTTL {
			cacheTTL = ttl
		}
	}

	for _, rr := range m.Ns {
		rrHdr, ttl := r.adjustRecordTTL(rr)

		if rrHdr.Rrtype == dns.TypeSOA {
			minTTL = int(rr.(*dns.SOA).Minttl)
		}

		if authTTL < 0 || ttl < authTTL {
			authTTL = ttl
		}
	}

	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return edns0, ""
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

	cacheTTLHistogram.Observe(float64(cacheTTL))

	if cacheTTL > r.CacheMaxTTL {
		cacheTTL = r.CacheMaxTTL
	} else if cacheTTL < r.CacheMinTTL {
		cacheTTL = r.CacheMinTTL
	}

	if cacheTTL == 0 {
		return edns0, ""
	}

	now := time.Now()
	entry := &cacheEntry{
		time:   now,
		expiry: now.Add(time.Duration(cacheTTL) * time.Second),
		qtype:  q.Qtype,
		qclass: q.Qclass,
		msg:    m,
		edns0:  edns0,
	}
	entry.hits.Store(1)

	matchType := "exact"
	if m.Rcode == dns.RcodeNameError {
		key = keyDomain
		matchType = "domain"
	}
	r.cache.Add(key, entry)
	cacheSize.Set(float64(r.cache.Len()))
	return edns0, matchType
}
