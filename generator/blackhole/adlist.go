package blackhole

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Doridian/foxDNS/handler"
	"github.com/miekg/dns"
)

type adlistContents = map[string]bool
type adlistMap = map[string]adlistContents

type Adlist struct {
	blockLists   adlistMap
	allowLists   adlistMap
	managedHosts map[string]string
	refreshLock  sync.Mutex

	config handler.Config

	mux             *dns.ServeMux
	handlerMap      map[string]dns.Handler
	refreshInterval time.Duration
	refreshCtx      context.Context
	refreshCancel   context.CancelFunc
}

var hardcodeIgnoredAdHosts = map[string]bool{
	"localhost.":             true,
	"localhost.localdomain.": true,
	"local.":                 true,
	"localdomain.":           true,
	"broadcasthost.":         true,
	"ip6-localhost.":         true,
	"ip6-loopback.":          true,
	"ip6-localnet.":          true,
	"ip6-mcastprefix.":       true,
	"ip6-allnodes.":          true,
	"ip6-allrouters.":        true,
	"ip6-allhosts.":          true,
	".":                      true,
}

func NewAdlist(blockLists []string, allowLists []string, mux *dns.ServeMux, refreshInterval time.Duration, config handler.Config) *Adlist {
	blockListsMap := make(adlistMap)
	for _, list := range blockLists {
		blockListsMap[list] = nil
	}
	allowListsMap := make(adlistMap)
	for _, list := range allowLists {
		allowListsMap[list] = nil
	}

	return &Adlist{
		blockLists:      blockListsMap,
		allowLists:      allowListsMap,
		mux:             mux,
		config:          config,
		handlerMap:      make(map[string]dns.Handler),
		managedHosts:    make(map[string]string),
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
	case "file", "":
		dataStream, err = os.Open(parsedUrl.Path)
	case "http", "https":
		var resp *http.Response
		resp, err = http.Get(list)
		if err == nil {
			dataStream = resp.Body
		}
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", parsedUrl.Scheme)
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
			if net.ParseIP(host) != nil {
				continue
			}

			host = dns.CanonicalName(host)
			if hardcodeIgnoredAdHosts[host] {
				continue
			}
			contents[host] = true
		}
	}

	return contents, nil
}

func (r *Adlist) getHandler(list string) dns.Handler {
	hdl, ok := r.handlerMap[list]
	if !ok {
		gen := New("adlist: " + list)
		hdl = handler.New(nil, gen, "", r.config)
		r.handlerMap[list] = hdl
	}
	return hdl
}

func (r *Adlist) Refresh() error {
	r.refreshLock.Lock()
	defer r.refreshLock.Unlock()

	newManagedHosts := make(map[string]string)

	for list, contents := range r.blockLists {
		newContents, err := r.loadList(list)
		if err == nil {
			r.blockLists[list] = newContents
			contents = newContents
		} else {
			log.Printf("Error loading blocklist %s: %v", list, err)
		}

		for host := range contents {
			if _, ok := newManagedHosts[host]; !ok {
				newManagedHosts[host] = list
			} else {
				newManagedHosts[host] += " & " + list
			}
		}
	}
	for list, contents := range r.allowLists {
		newContents, err := r.loadList(list)
		if err == nil {
			r.allowLists[list] = newContents
			contents = newContents
		} else {
			log.Printf("Error loading allowlist %s: %v", list, err)
		}

		for host := range contents {
			delete(newManagedHosts, host)
		}
	}

	usedHandlers := make(map[string]bool)
	removed := 0
	added := 0
	for host := range r.managedHosts {
		if _, ok := newManagedHosts[host]; !ok {
			r.mux.HandleRemove(host)
			removed++
		}
	}
	for host, list := range newManagedHosts {
		usedHandlers[list] = true
		if _, ok := r.managedHosts[host]; !ok {
			r.mux.Handle(host, r.getHandler(list))
			added++
		}
	}
	r.managedHosts = newManagedHosts

	for list := range r.handlerMap {
		if !usedHandlers[list] {
			delete(r.handlerMap, list)
		}
	}

	log.Printf(
		"Adlists refreshed, %d hosts managed with %d handlers (%d added, %d removed)",
		len(r.managedHosts),
		len(r.handlerMap),
		added,
		removed,
	)

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
