package resolver

import (
	"log"
	"math/rand"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type querySlotInfo struct {
	conn         *dns.Conn
	server       *ServerConfig
	serverCookie []byte
	lastUse      time.Time
}

var (
	openConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "foxdns_resolver_open_connections_total",
		Help: "The number of open connections to upstream resolvers",
	}, []string{"server"})
)

func (r *Generator) acquireQuerySlot(currentTry int) (info *querySlotInfo, err error) {
	var server *ServerConfig
	switch r.ServerStrategy {
	case StrategyRoundRobin:
		server = r.Servers[r.lastServerIdx]
		nextServerIdx := r.lastServerIdx + 1
		if nextServerIdx >= len(r.Servers) {
			nextServerIdx = 0
		}
		r.lastServerIdx = nextServerIdx
	case StrategyRandom:
		server = r.Servers[rand.Int()%len(r.Servers)]
	case StrategyFailover:
		server = r.Servers[(currentTry-1)%len(r.Servers)]
	}

	server.querySlotCond.L.Lock()

	for {
		firstElem := server.freeQuerySlots.Front()
		if firstElem != nil {
			info = server.freeQuerySlots.Remove(firstElem).(*querySlotInfo)
			server.querySlotCond.L.Unlock()
			return
		}

		if server.inFlightQueries < server.MaxParallelQueries {
			server.inFlightQueries++
			openConnections.WithLabelValues(server.Addr).Set(float64(server.inFlightQueries))

			server.querySlotCond.L.Unlock()
			info = &querySlotInfo{
				server:       server,
				serverCookie: []byte{},
			}
			info.conn, err = server.client.Dial(server.Addr)
			return
		}

		server.querySlotCond.Wait()
	}
}

func (r *Generator) returnQuerySlot(info *querySlotInfo, err error) {
	if info == nil {
		return
	}

	server := info.server

	server.querySlotCond.L.Lock()
	defer server.querySlotCond.L.Unlock()

	if err == nil {
		info.lastUse = r.CurrentTime()
		server.freeQuerySlots.PushFront(info)
	} else {
		log.Printf("Returning upstream connection to %s with error %v", info.server.Addr, err)
		server.inFlightQueries--
		openConnections.WithLabelValues(server.Addr).Set(float64(server.inFlightQueries))
		if info.conn != nil {
			go info.conn.Close()
		}
	}

	server.querySlotCond.Signal()
}

func (r *Generator) cleanupServerQuerySlots(server *ServerConfig) {
	server.querySlotCond.L.Lock()
	defer server.querySlotCond.L.Unlock()

	madeChanges := false

	for {
		lastElem := server.freeQuerySlots.Back()
		if lastElem == nil {
			break
		}
		info := lastElem.Value.(*querySlotInfo)

		if time.Since(info.lastUse) > r.MaxIdleTime {
			server.freeQuerySlots.Remove(lastElem)
			server.inFlightQueries--
			openConnections.WithLabelValues(server.Addr).Set(float64(server.inFlightQueries))
			go info.conn.Close()
			madeChanges = true
		} else {
			break
		}
	}

	if madeChanges {
		server.querySlotCond.Signal()
	}
}

func (r *Generator) cleanupAllQuerySlots() {
	for _, server := range r.Servers {
		r.cleanupServerQuerySlots(server)
	}
}
