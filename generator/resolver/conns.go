package resolver

import (
	"log"
	"math/rand"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type connInfo struct {
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

func (r *Generator) acquireConn(currentTry int) (info *connInfo, err error) {
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

	server.connCond.L.Lock()

	for {
		firstElem := server.freeConnections.Front()
		if firstElem != nil {
			info = server.freeConnections.Remove(firstElem).(*connInfo)
			server.connCond.L.Unlock()
			return
		}

		if server.connections < r.MaxConnections {
			server.connections++
			openConnections.WithLabelValues(server.Addr).Set(float64(server.connections))

			server.connCond.L.Unlock()
			info = &connInfo{
				server:       server,
				serverCookie: []byte{},
			}
			info.conn, err = server.client.Dial(server.Addr)
			return
		}

		server.connCond.Wait()
	}
}

func (r *Generator) returnConn(info *connInfo, err error) {
	if info == nil {
		return
	}

	server := info.server

	server.connCond.L.Lock()
	defer server.connCond.L.Unlock()

	if err == nil {
		info.lastUse = r.CurrentTime()
		server.freeConnections.PushFront(info)
	} else {
		log.Printf("Returning upstream connection to %s with error %v", info.server.Addr, err)
		server.connections--
		openConnections.WithLabelValues(server.Addr).Set(float64(server.connections))
		if info.conn != nil {
			go info.conn.Close()
		}
	}

	server.connCond.Signal()
}

func (r *Generator) cleanupServerConns(server *ServerConfig) {
	server.connCond.L.Lock()
	defer server.connCond.L.Unlock()

	madeChanges := false

	for {
		lastElem := server.freeConnections.Back()
		if lastElem == nil {
			break
		}
		info := lastElem.Value.(*connInfo)

		if time.Since(info.lastUse) > r.MaxIdleTime {
			server.freeConnections.Remove(lastElem)
			server.connections--
			openConnections.WithLabelValues(server.Addr).Set(float64(server.connections))
			go info.conn.Close()
			madeChanges = true
		} else {
			break
		}
	}

	if madeChanges {
		server.connCond.Signal()
	}
}

func (r *Generator) cleanupConns() {
	for _, server := range r.Servers {
		r.cleanupServerConns(server)
	}
}
