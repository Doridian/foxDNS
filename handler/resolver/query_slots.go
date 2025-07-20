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

func (s *querySlotInfo) close() {
	if s.conn == nil {
		return
	}
	_ = s.conn.Close()
}

var (
	openConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "foxdns_resolver_open_connections_total",
		Help: "The number of open connections to upstream resolvers",
	}, []string{"server"})
)

func (g *Generator) acquireQuerySlot(currentTry int) (info *querySlotInfo, err error) {
	var server *ServerConfig
	switch g.ServerStrategy {
	case StrategyRoundRobin:
		server = g.Servers[g.lastServerIdx]
		nextServerIdx := g.lastServerIdx + 1
		if nextServerIdx >= len(g.Servers) {
			nextServerIdx = 0
		}
		g.lastServerIdx = nextServerIdx
	case StrategyRandom:
		server = g.Servers[rand.Int()%len(g.Servers)]
	case StrategyFailover:
		server = g.Servers[(currentTry-1)%len(g.Servers)]
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

func (g *Generator) returnQuerySlot(info *querySlotInfo, err error) {
	if info == nil {
		return
	}

	server := info.server

	server.querySlotCond.L.Lock()
	defer server.querySlotCond.L.Unlock()

	if err == nil {
		info.lastUse = g.CurrentTime()
		server.freeQuerySlots.PushFront(info)
	} else {
		log.Printf("Returning upstream connection to %s with error %v", info.server.Addr, err)
		server.inFlightQueries--
		openConnections.WithLabelValues(server.Addr).Set(float64(server.inFlightQueries))
		if info.conn != nil {
			go info.close()
		}
	}

	server.querySlotCond.Signal()
}

func (g *Generator) cleanupServerQuerySlots(server *ServerConfig) {
	server.querySlotCond.L.Lock()
	defer server.querySlotCond.L.Unlock()

	madeChanges := false

	for {
		lastElem := server.freeQuerySlots.Back()
		if lastElem == nil {
			break
		}
		info := lastElem.Value.(*querySlotInfo)

		if time.Since(info.lastUse) > g.MaxIdleTime {
			server.freeQuerySlots.Remove(lastElem)
			server.inFlightQueries--
			openConnections.WithLabelValues(server.Addr).Set(float64(server.inFlightQueries))
			go info.close()
			madeChanges = true
		} else {
			break
		}
	}

	if madeChanges {
		server.querySlotCond.Signal()
	}
}

func (g *Generator) cleanupAllQuerySlots() {
	for _, server := range g.Servers {
		g.cleanupServerQuerySlots(server)
	}
}
