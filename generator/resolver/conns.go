package resolver

import (
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
	openConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "foxdns_resolver_open_connections_total",
		Help: "The number of open connections to upstream resolvers",
	})
)

func (r *Generator) acquireConn() (info *connInfo, err error) {
	r.connCond.L.Lock()

	for {
		firstElem := r.freeConnections.Front()
		if firstElem != nil {
			info = r.freeConnections.Remove(firstElem).(*connInfo)
			r.connCond.L.Unlock()
			return
		}

		if r.connections < r.MaxConnections {
			r.connections++
			openConnections.Set(float64(r.connections))

			srv := r.Servers[r.lastServerIdx]
			r.lastServerIdx++
			if r.lastServerIdx >= len(r.Servers) {
				r.lastServerIdx = 0
			}

			r.connCond.L.Unlock()
			info = &connInfo{
				server:       srv,
				serverCookie: []byte{},
			}
			info.conn, err = srv.client.Dial(srv.Addr)
			return
		}

		r.connCond.Wait()
	}
}

func (r *Generator) returnConn(info *connInfo, err error) {
	if info == nil {
		return
	}

	r.connCond.L.Lock()
	defer r.connCond.L.Unlock()

	if err == nil {
		info.lastUse = time.Now()
		r.freeConnections.PushFront(info)
	} else {
		r.connections--
		openConnections.Set(float64(r.connections))
		if info.conn != nil {
			go info.conn.Close()
		}
	}

	r.connCond.Signal()
}

func (r *Generator) cleanupConns() {
	r.connCond.L.Lock()
	defer r.connCond.L.Unlock()

	madeChanges := false

	for {
		lastElem := r.freeConnections.Back()
		if lastElem == nil {
			break
		}
		info := lastElem.Value.(*connInfo)

		if time.Since(info.lastUse) > r.MaxIdleTime {
			r.freeConnections.Remove(lastElem)
			r.connections--
			openConnections.Set(float64(r.connections))
			go info.conn.Close()
			madeChanges = true
		} else {
			break
		}
	}

	if madeChanges {
		r.connCond.Signal()
	}
}
