package static

import (
	"io"
	"log"
	"os"

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
	configs []zoneConfig
	records map[uint16]map[string][]dns.RR
	watcher *fsnotify.Watcher
}

func New() *Generator {
	return &Generator{
		configs: make([]zoneConfig, 0),
		records: make(map[uint16]map[string][]dns.RR),
		watcher: nil,
	}
}

func (r *Generator) LoadZoneFile(file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	fh, err := os.Open(file)
	if err != nil {
		return err
	}
	err = r.loadZone(fh, file, origin, defaultTTL, includeAllowed)
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

func (r *Generator) addRecord(rr dns.RR) {
	hdr := rr.Header()

	hdr.Name = dns.CanonicalName(hdr.Name)
	recType := hdr.Rrtype

	typedRecs := r.records[recType]
	if typedRecs == nil {
		typedRecs = make(map[string][]dns.RR)
		r.records[recType] = typedRecs
	}

	zoneRecs := typedRecs[hdr.Name]
	if zoneRecs == nil {
		zoneRecs = []dns.RR{}
	}
	typedRecs[hdr.Name] = append(zoneRecs, rr)
}

func (r *Generator) HandleQuestion(q dns.Question, wr dns.ResponseWriter) []dns.RR {
	typedRecs := r.records[q.Qtype]
	if typedRecs == nil {
		return []dns.RR{}
	}

	zoneRecs := typedRecs[q.Name]
	if zoneRecs == nil {
		return []dns.RR{}
	}

	return zoneRecs
}

func (r *Generator) Refresh() error {
	oldRecords := r.records
	r.records = make(map[uint16]map[string][]dns.RR)
	for _, cf := range r.configs {
		err := r.LoadZoneFile(cf.file, cf.origin, cf.defaultTTL, cf.includeAllowed)
		if err != nil {
			r.records = oldRecords
			return err
		}
	}
	return nil
}

func (r *Generator) Start() error {
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
