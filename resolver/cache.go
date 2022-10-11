package resolver

import (
	"fmt"
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

func (r *Resolver) SetCacheSize(size int) {
	r.cache.Resize(size)
}

func cacheKey(q *dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)
}

func (r *Resolver) getFromCache(q *dns.Question) *dns.Msg {
	key := cacheKey(q)

	res, ok := r.cache.Get(key)
	if !ok {
		return nil
	}

	entry := res.(*cacheEntry)
	now := time.Now()
	if entry.expiry.Before(now) {
		return nil
	}

	ttlAdjust := uint32(now.Sub(entry.time).Seconds())

	msg := entry.msg.Copy()

	for _, rr := range msg.Answer {
		rr.Header().Ttl -= ttlAdjust
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl -= ttlAdjust
	}

	return msg
}

func (r *Resolver) writeToCache(q *dns.Question, m *dns.Msg) {
	if m.Rcode != dns.RcodeSuccess {
		return
	}

	key := cacheKey(q)

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
