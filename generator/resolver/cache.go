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
}

var (
	cacheResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "foxdns_resolver_cache_results",
		Help: "The number of cache hits/misses for DNS queries",
	}, []string{"result"})
)

func (r *Generator) SetCacheSize(size int) {
	r.cache.Resize(size)
}

func cacheKey(q *dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)
}

func (r *Generator) getOrAddCache(q *dns.Question) (*dns.Msg, error) {
	key := cacheKey(q)

	entry := r.getFromCache(key)
	if entry != nil {
		cacheResults.WithLabelValues("hit").Inc()
		return entry, nil
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	cacheLock, loaded := r.cacheLock.LoadOrStore(key, wg)
	cacheLockWG := cacheLock.(*sync.WaitGroup)

	if loaded {
		cacheLockWG.Wait()

		entry := r.getFromCache(key)
		if entry != nil {
			cacheResults.WithLabelValues("wait").Inc()
			return entry, nil
		}
	} else {
		defer func() {
			r.cacheLock.Delete(key)
			wg.Done()
		}()
	}

	reply, err := r.exchangeWithRetry(q)
	if err != nil {
		return nil, err
	}

	r.writeToCache(key, reply)
	cacheResults.WithLabelValues("miss").Inc()
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
}

func (r *Generator) getFromCache(key string) *dns.Msg {
	entry, ok := r.cache.Get(key)
	if !ok {
		return nil
	}

	now := time.Now()
	if entry.expiry.Before(now) {
		return nil
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

	return msg
}

func (r *Generator) writeToCache(key string, m *dns.Msg) {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return
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

	now := time.Now()
	entry := &cacheEntry{
		time:   now,
		expiry: now.Add(time.Duration(cacheTTL) * time.Second),
		msg:    m,
	}

	r.cache.Add(key, entry)
}
