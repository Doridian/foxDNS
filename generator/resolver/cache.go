package resolver

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const cacheMaxTTL = 3600
const cacheNoReplyTTL = 30

type cacheEntry struct {
	msg    *dns.Msg
	time   time.Time
	expiry time.Time
}

func (r *Generator) SetCacheSize(size int) {
	r.cache.Resize(size)
}

func cacheKey(q *dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)
}

func (r *Generator) getOrAddCache(q *dns.Question) (*dns.Msg, error) {
	key := cacheKey(q)

	entry := r.getFromCache(key, false)
	if entry != nil {
		return entry, nil
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	cacheLock, loaded := r.cacheLock.LoadOrStore(key, wg)
	cacheLockWG := cacheLock.(*sync.WaitGroup)

	if loaded {
		cacheLockWG.Wait()

		entry := r.getFromCache(key, true)
		if entry != nil {
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
	return reply, nil
}

func (r *Generator) getFromCache(key string, allowChange bool) *dns.Msg {
	res, ok := r.cache.Get(key)
	if !ok {
		return nil
	}

	entry := res.(*cacheEntry)
	now := time.Now()
	if entry.expiry.Before(now) {
		if allowChange {
			r.cache.Remove(key)
		}
		return nil
	}

	ttlAdjust := uint32(now.Sub(entry.time).Seconds())

	msg := entry.msg.Copy()

	if ttlAdjust > 1 {
		ttlAdjust--
		for _, rr := range msg.Answer {
			rr.Header().Ttl -= ttlAdjust
		}
		for _, rr := range msg.Ns {
			rr.Header().Ttl -= ttlAdjust
		}
	}

	return msg
}

func (r *Generator) writeToCache(key string, m *dns.Msg) {
	if m.Rcode != dns.RcodeSuccess {
		return
	}

	cacheTTL := -1

	for _, rr := range m.Answer {
		ttl := int(rr.Header().Ttl)
		if cacheTTL < 0 || ttl < cacheTTL {
			cacheTTL = ttl
		}
	}

	for _, rr := range m.Ns {
		ttl := int(rr.Header().Ttl)
		if cacheTTL < 0 || ttl < cacheTTL {
			cacheTTL = ttl
		}
	}

	if cacheTTL < 0 {
		cacheTTL = cacheNoReplyTTL
	} else if cacheTTL > cacheMaxTTL {
		cacheTTL = cacheMaxTTL
	}

	now := time.Now()
	entry := &cacheEntry{
		time:   now,
		expiry: now.Add(time.Duration(cacheTTL) * time.Second),
		msg:    m,
	}

	r.cache.Add(key, entry)
}
