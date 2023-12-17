package resolver

import (
	"time"

	"github.com/miekg/dns"
)

type connInfo struct {
	conn    *dns.Conn
	lastUse time.Time
}

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

			srv := r.Servers[r.lastServerIdx]
			r.lastServerIdx++
			if r.lastServerIdx >= len(r.Servers) {
				r.lastServerIdx = 0
			}

			r.connCond.L.Unlock()
			info = &connInfo{}
			info.conn, err = r.Client.Dial(srv)
			return
		}

		r.connCond.Wait()
	}
}

func (r *Generator) returnConn(info *connInfo, err error) {
	r.connCond.L.Lock()
	defer r.connCond.L.Unlock()

	if err == nil {
		info.lastUse = time.Now()
		r.freeConnections.PushBack(info)
	} else {
		r.connections--
		go info.conn.Close()
	}

	r.connCond.Signal()
}

func (r *Generator) cleanupConns() {
	r.connCond.L.Lock()
	defer r.connCond.L.Unlock()

	madeChanges := false

	for {
		firstElem := r.freeConnections.Front()
		if firstElem == nil {
			break
		}
		info := firstElem.Value.(*connInfo)

		if time.Since(info.lastUse) > r.MaxIdleTime {
			r.freeConnections.Remove(firstElem)
			r.connections--
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
