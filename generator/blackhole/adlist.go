package blackhole

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type adlistContents = map[string]bool
type adlistMap = map[string]adlistContents

type Adlist struct {
	blockLists   adlistMap
	allowLists   adlistMap
	managedHosts map[string]bool
	refreshLock  sync.Mutex

	mux             *dns.ServeMux
	handler         *Generator
	refreshInterval time.Duration
	refreshCtx      context.Context
	refreshCancel   context.CancelFunc
}

var hardcodeIgnoredAdHosts = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"local":                 true,
	"localdomain":           true,
	"broadcasthost":         true,
	"ip6-localhost":         true,
	"ip6-loopback":          true,
	"ip6-localnet":          true,
	"ip6-mcastprefix":       true,
	"ip6-allnodes":          true,
	"ip6-allrouters":        true,
	"ip6-allhosts":          true,
}

func NewAdlist(blockLists []string, allowLists []string, mux *dns.ServeMux, refreshInterval time.Duration) *Adlist {
	blockListsMap := make(adlistMap)
	for _, list := range blockLists {
		blockListsMap[list] = make(adlistContents)
	}
	allowListsMap := make(adlistMap)
	for _, list := range allowLists {
		allowListsMap[list] = make(adlistContents)
	}

	return &Adlist{
		blockLists:      blockListsMap,
		allowLists:      allowListsMap,
		mux:             mux,
		handler:         New("adlist"),
		managedHosts:    make(map[string]bool),
		refreshInterval: refreshInterval,
	}
}

func (r *Adlist) loadList(list string) (adlistContents, error) {
	var bodyStr string

	parsedUrl, err := url.Parse(list)
	if err != nil {
		return nil, err
	}

	var dataStream io.ReadCloser

	switch parsedUrl.Scheme {
	case "file":
		dataStream, err = os.Open(parsedUrl.Path)
	case "http", "https":
		var resp *http.Response
		resp, err = http.Get(list)
		if err == nil {
			dataStream = resp.Body
		}
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = dataStream.Close()
	}()

	body, err := io.ReadAll(dataStream)
	if err != nil {
		return nil, err
	}

	bodyStr = string(body)

	contents := make(adlistContents)
	bodyStr = strings.ReplaceAll(bodyStr, "\r", "\n")
	for _, line := range strings.Split(bodyStr, "\n") {
		if line == "" {
			continue
		}
		hashPos := strings.Index(line, "#")
		if hashPos == 0 {
			continue
		}
		if hashPos > 0 {
			line = line[:hashPos]
		}
		line = strings.Trim(line, " ")
		if line == "" {
			continue
		}

		split := strings.Split(strings.ReplaceAll(line, "\t", " "), " ")
		for _, host := range split {
			host = strings.Trim(host, ". ")
			if host == "" {
				continue
			}
			if hardcodeIgnoredAdHosts[host] {
				continue
			}
			if net.ParseIP(host) != nil {
				continue
			}
			contents[host] = true
		}
	}

	return contents, nil
}

func (r *Adlist) Refresh() error {
	r.refreshLock.Lock()
	defer r.refreshLock.Unlock()

	newManagedHosts := make(map[string]bool)

	for list := range r.blockLists {
		contents, err := r.loadList(list)
		if err == nil {
			r.blockLists[list] = contents
		} else {
			log.Printf("Error loading blocklist %s: %v", list, err)
		}

		for host := range contents {
			newManagedHosts[host] = true
		}
	}
	for list := range r.allowLists {
		contents, err := r.loadList(list)
		if err == nil {
			r.allowLists[list] = contents
		} else {
			log.Printf("Error loading allowlist %s: %v", list, err)
		}

		for host := range contents {
			delete(newManagedHosts, host)
		}
	}

	removed := 0
	added := 0
	for host := range r.managedHosts {
		if !newManagedHosts[host] {
			r.mux.HandleRemove(host)
			removed++
		}
	}
	for host := range newManagedHosts {
		if !r.managedHosts[host] {
			r.mux.Handle(host, r.handler)
			added++
		}
	}
	r.managedHosts = newManagedHosts

	log.Printf("Adlists refreshed, %d hosts managed (%d added, %d removed)", len(r.managedHosts), added, removed)

	return nil
}

func (r *Adlist) refreshLoop() {
	for {
		select {
		case <-time.After(r.refreshInterval):
			err := r.Refresh()
			if err != nil {
				log.Printf("Error refreshing adlist: %s", err)
			}
		case <-r.refreshCtx.Done():
			return
		}
	}
}

func (r *Adlist) Start() error {
	r.refreshCtx, r.refreshCancel = context.WithCancel(context.Background())
	go r.refreshLoop()
	return r.Refresh()
}

func (r *Adlist) Stop() error {
	r.refreshCancel()
	return nil
}

func (r *Adlist) GetName() string {
	return "adlist"
}
