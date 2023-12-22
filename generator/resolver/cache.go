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
	msg    *dns.Msg
	time   time.Time
	expiry time.Time
	qtype  uint16
	qclass uint16
	hits   atomic.Uint64
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
		Help:    "Upstream TTLs for DNS cache entries",
		Buckets: []float64{1, 10, 30, 60, 300, 600, 1800, 3600},
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

func (r *Generator) getOrAddCache(q *dns.Question, forceRequery bool) (*dns.Msg, error) {
	key := cacheKey(q)
	keyDomain := cacheKeyDomain(q)

	if !forceRequery {
		entry, matchType := r.getFromCache(key, keyDomain, q)
		if entry != nil {
			cacheResults.WithLabelValues("hit", matchType).Inc()
			return entry, nil
		}
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	defer wg.Done()
	cacheLock, loaded := r.cacheLock.LoadOrStore(key, wg)
	cacheLockWG := cacheLock.(*sync.WaitGroup)

	if loaded {
		if forceRequery {
			return nil, nil
		}

		cacheLockWG.Wait()

		entry, matchType := r.getFromCache(key, keyDomain, q)
		if entry != nil {
			// Can't be  hit when forceRequery is true
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

	edns0Index := -1
	downstreamEdns0 := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	downstreamEdns0.SetUDPSize(util.DNSMaxSize)

	for idx, rr := range reply.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			continue
		}

		edns0Index = idx
		downstreamEdns0.Hdr.Ttl = rr.Header().Ttl
		break
	}

	if edns0Index >= 0 {
		reply.Extra[edns0Index] = downstreamEdns0
	} else {
		reply.Extra = append(reply.Extra, downstreamEdns0)
	}

	matchType := r.writeToCache(key, keyDomain, q, reply)
	if !forceRequery {
		cacheResults.WithLabelValues("miss", matchType).Inc()
	}
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

func (r *Generator) adjustRecordTTL(rr dns.RR, ttlAdjust uint32) {
	rrHdr := rr.Header()
	if rrHdr.Rrtype == dns.TypeOPT {
		// TTL in OPT records is special and not actually a TTL
		return
	}

	if rrHdr.Ttl < ttlAdjust {
		rrHdr.Ttl = 0
	} else {
		rrHdr.Ttl -= ttlAdjust
	}

	if rrHdr.Ttl < r.RecordMinTTL {
		rrHdr.Ttl = r.RecordMinTTL
	} else if rrHdr.Ttl > r.RecordMaxTTL {
		rrHdr.Ttl = r.RecordMaxTTL
	}
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

	entry.hits.Add(1)

	ttlAdjust := uint32(now.Sub(entry.time).Seconds())

	msg := entry.msg.Copy()

	if ttlAdjust > 1 {
		ttlAdjust--
		for _, rr := range msg.Answer {
			r.adjustRecordTTL(rr, ttlAdjust)
		}
		for _, rr := range msg.Ns {
			r.adjustRecordTTL(rr, ttlAdjust)
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

	cacheTTLHistogram.Observe(float64(cacheTTL))

	if cacheTTL > r.CacheMaxTTL {
		cacheTTL = r.CacheMaxTTL
	} else if cacheTTL < r.CacheMinTTL {
		cacheTTL = r.CacheMinTTL
	}

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
	entry.hits.Store(1)

	matchType := "exact"
	if m.Rcode == dns.RcodeNameError {
		key = keyDomain
		matchType = "domain"
	}
	r.cache.Add(key, entry)
	cacheSize.Set(float64(r.cache.Len()))
	return matchType
}
