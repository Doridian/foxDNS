package static

import (
	"io"
	"os"

	"github.com/miekg/dns"
)

type Generator struct {
	records map[uint16]map[string][]dns.RR
}

func New() *Generator {
	return &Generator{
		records: make(map[uint16]map[string][]dns.RR),
	}
}

func (r *Generator) LoadZoneFile(file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	fh, err := os.Open(file)
	if err != nil {
		return err
	}
	return r.LoadZone(fh, file, origin, defaultTTL, includeAllowed)
}

func (r *Generator) LoadZone(rd io.Reader, file string, origin string, defaultTTL uint32, includeAllowed bool) error {
	parser := dns.NewZoneParser(rd, origin, file)
	parser.SetDefaultTTL(defaultTTL)
	parser.SetIncludeAllowed(includeAllowed)

	for {
		rr, ok := parser.Next()
		if !ok || rr == nil {
			return parser.Err()
		}
		r.AddRecord(rr)
	}
}

func (r *Generator) AddRecord(rr dns.RR) {
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
