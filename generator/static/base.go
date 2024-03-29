package static

import (
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/Doridian/foxDNS/util"
	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
)

type zoneConfig struct {
	file           string
	origin         string
	defaultTTL     uint32
	includeAllowed bool
}

type Generator struct {
	configs        []zoneConfig
	records        map[string]map[uint16][]dns.RR
	recordsLock    sync.RWMutex
	watcher        *fsnotify.Watcher
	enableFSNotify bool
	cnameResolver  dns.Handler
}

func New(enableFSNotify bool, cnameResolver dns.Handler) *Generator {
	return &Generator{
		configs:        make([]zoneConfig, 0),
		records:        make(map[string]map[uint16][]dns.RR),
		watcher:        nil,
		enableFSNotify: enableFSNotify,
		cnameResolver:  cnameResolver,
	}
}

func (r *Generator) LoadZoneFile(file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	r.recordsLock.Lock()
	defer r.recordsLock.Unlock()

	err := r.loadZoneFile(file, origin, defaultTTL, includeAllowed)
	if err != nil {
		return err
	}

	r.configs = append(r.configs, zoneConfig{
		file:           file,
		origin:         origin,
		defaultTTL:     defaultTTL,
		includeAllowed: includeAllowed,
	})

	if r.watcher != nil {
		err = r.watcher.Add(file)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Generator) loadZoneFile(file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	fh, err := os.Open(file)
	if err != nil {
		return err
	}
	return r.loadZone(fh, file, origin, defaultTTL, includeAllowed)
}

func (r *Generator) LoadZone(rd io.Reader, file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	r.recordsLock.Lock()
	defer r.recordsLock.Unlock()
	return r.loadZone(rd, file, origin, defaultTTL, includeAllowed)
}

func (r *Generator) loadZone(rd io.Reader, file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	parser := dns.NewZoneParser(rd, origin, file)
	parser.SetDefaultTTL(defaultTTL)
	parser.SetIncludeAllowed(includeAllowed)

	for {
		rr, ok := parser.Next()
		if !ok || rr == nil {
			return parser.Err()
		}
		r.addRecord(rr)
	}
}

func (r *Generator) AddRecord(rr dns.RR) {
	r.recordsLock.Lock()
	defer r.recordsLock.Unlock()
	r.addRecord(rr)
}

func (r *Generator) addRecord(rr dns.RR) {
	hdr := rr.Header()
	if hdr.Class != dns.ClassINET {
		return
	}

	hdr.Name = dns.CanonicalName(hdr.Name)

	nameRecs := r.records[hdr.Name]
	if nameRecs == nil {
		nameRecs = make(map[uint16][]dns.RR)
		r.records[hdr.Name] = nameRecs
	}

	typeRecs := nameRecs[hdr.Rrtype]
	if typeRecs == nil {
		typeRecs = []dns.RR{}
	}
	nameRecs[hdr.Rrtype] = append([]dns.RR{rr}, typeRecs...)
}

func (r *Generator) HandleQuestion(q *dns.Question, wr util.SimpleDNSResponseWriter) ([]dns.RR, bool) {
	r.recordsLock.RLock()

	nameRecs := r.records[q.Name]
	if nameRecs == nil {
		r.recordsLock.RUnlock()
		return []dns.RR{}, true
	}

	typedRecs := nameRecs[q.Qtype]
	if typedRecs != nil || q.Qtype == dns.TypeCNAME {
		r.recordsLock.RUnlock()
		if typedRecs == nil {
			return []dns.RR{}, false
		}
		return typedRecs, false
	}

	// Handle CNAMEs
	cnameRecs := nameRecs[dns.TypeCNAME]
	if cnameRecs == nil || len(cnameRecs) != 1 {
		r.recordsLock.RUnlock()
		return []dns.RR{}, false
	}

	cname := cnameRecs[0].(*dns.CNAME)
	r.recordsLock.RUnlock()

	var subRes []dns.RR
	if r.cnameResolver != nil {
		subWR := util.NewResponseWriter(wr, &net.TCPAddr{
			IP:   net.IP([]byte{127, 0, 0, 1}),
			Port: 53,
		})
		r.cnameResolver.ServeDNS(subWR, &dns.Msg{
			Question: []dns.Question{
				{
					Name:   cname.Target,
					Qtype:  q.Qtype,
					Qclass: q.Qclass,
				},
			},
		})
		if subWR.Result != nil && subWR.Result.Rcode == dns.RcodeSuccess {
			subRes = subWR.Result.Answer
		}
	} else {
		subRes, _ = r.HandleQuestion(&dns.Question{
			Name:   cname.Target,
			Qtype:  q.Qtype,
			Qclass: q.Qclass,
		}, wr)
	}

	if subRes == nil {
		return []dns.RR{cname}, false
	}

	resultRecs := make([]dns.RR, len(subRes)+1)
	resultRecs[0] = cname
	copy(resultRecs[1:], subRes)
	return resultRecs, false
}

func (r *Generator) Refresh() error {
	r.recordsLock.Lock()
	defer r.recordsLock.Unlock()

	r.records = make(map[string]map[uint16][]dns.RR)
	for _, cf := range r.configs {
		err := r.loadZoneFile(cf.file, cf.origin, cf.defaultTTL, cf.includeAllowed)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Generator) Start() error {
	if !r.enableFSNotify {
		return nil
	}

	var err error
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	r.watcher = watcher

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					log.Printf("Reloading static generator because of file %s", event.Name)
					err := r.Refresh()
					if err != nil {
						log.Printf("Error reloading zone: %v", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("fsnotify error: %v", err)
			}
		}
	}()

	for _, cf := range r.configs {
		err = r.watcher.Add(cf.file)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Generator) Stop() error {
	err := r.watcher.Close()
	if err != nil {
		return err
	}
	r.watcher = nil
	return nil
}

func (r *Generator) GetName() string {
	return "static"
}
