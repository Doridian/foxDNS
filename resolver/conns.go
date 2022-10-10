package resolver

import "github.com/miekg/dns"

func (r *Resolver) acquireConn() (conn *dns.Conn, err error) {
	r.connCond.L.Lock()

	for {
		firstElem := r.freeConnections.Front()
		if firstElem != nil {
			conn = r.freeConnections.Remove(firstElem).(*dns.Conn)
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
			conn, err = r.Client.Dial(srv)
			return
		}

		r.connCond.Wait()
	}
}

func (r *Resolver) returnConn(conn *dns.Conn, err error) {
	r.connCond.L.Lock()
	defer r.connCond.L.Unlock()

	if err == nil {
		r.freeConnections.PushBack(conn)
	} else {
		r.connections--
	}

	r.connCond.Signal()
}
