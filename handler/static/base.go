package static

import (
	"io"
	"log"
	"net"
	"os"
	"sync"

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
}

func New(enableFSNotify bool) *Generator {
	return &Generator{
		configs:        make([]zoneConfig, 0),
		records:        make(map[string]map[uint16][]dns.RR),
		watcher:        nil,
		enableFSNotify: enableFSNotify,
	}
}

func (r *Generator) LoadZoneFile(file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	r.recordsLock.Lock()
	defer r.recordsLock.Unlock()
	return r.loadZoneFile(file, origin, defaultTTL, includeAllowed)
}

func (r *Generator) LoadZone(rd io.Reader, file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	r.recordsLock.Lock()
	defer r.recordsLock.Unlock()
	return r.loadZone(rd, file, origin, defaultTTL, includeAllowed)
}

func (r *Generator) loadZoneFile(file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	fh, err := os.Open(file)
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

	return r.loadZone(fh, file, origin, defaultTTL, includeAllowed)
}

func (r *Generator) loadZone(rd io.Reader, file string, origin string, defaultTTL uint32, includeAllowed bool) (err error) {
	origin = dns.CanonicalName(origin)

	parser := dns.NewZoneParser(rd, origin, file)
	parser.SetDefaultTTL(defaultTTL)
	parser.SetIncludeAllowed(includeAllowed)

	for {
		rr, ok := parser.Next()
		if !ok || rr == nil {
			err = parser.Err()
			return
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

func (r *Generator) findAuthorityRecords(q *dns.Question, rcodeNameError int) ([]dns.RR, []dns.RR, []dns.EDNS0, int) {
	for off, end := 0, false; !end; off, end = dns.NextLabel(q.Name, off) {
		name := q.Name[off:]

		nameRecs := r.records[name]
		if nameRecs == nil {
			continue
		}

		typedRecs := nameRecs[dns.TypeSOA]
		if len(typedRecs) > 0 {
			return nil, typedRecs, nil, rcodeNameError
		}

		typedRecs = nameRecs[dns.TypeNS]
		if len(typedRecs) > 0 {
			return nil, typedRecs, nil, dns.RcodeSuccess
		}
	}

	return nil, nil, nil, rcodeNameError
}

func (r *Generator) HandleQuestion(q *dns.Question, recurse bool, dnssec bool, _ net.IP) ([]dns.RR, []dns.RR, []dns.EDNS0, int) {
	r.recordsLock.RLock()
	defer r.recordsLock.RUnlock()

	nameRecs := r.records[q.Name]
	if len(nameRecs) == 0 {
		return r.findAuthorityRecords(q, dns.RcodeNameError)
	}

	typedRecs := nameRecs[q.Qtype]
	if len(typedRecs) > 0 {
		return typedRecs, nil, nil, dns.RcodeSuccess
	}

	if q.Qtype == dns.TypeCNAME {
		return r.findAuthorityRecords(q, dns.RcodeSuccess)
	}

	typedRecs = nameRecs[dns.TypeCNAME]
	if len(typedRecs) == 0 {
		return r.findAuthorityRecords(q, dns.RcodeSuccess)
	}

	cname := typedRecs[0].(*dns.CNAME)

	localResolvedRecs, _, _, _ := r.HandleQuestion(&dns.Question{
		Name:   cname.Target,
		Qtype:  q.Qtype,
		Qclass: q.Qclass,
	}, recurse, dnssec, nil)

	if localResolvedRecs != nil {
		typedRecs = append(typedRecs, localResolvedRecs...)
	}

	return typedRecs, nil, nil, dns.RcodeSuccess
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
