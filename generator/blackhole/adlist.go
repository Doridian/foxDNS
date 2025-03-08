package blackhole

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Adlist struct {
	url             string
	mux             *dns.ServeMux
	handler         *Generator
	refreshInterval time.Duration
	refreshCtx      context.Context
	refreshCancel   context.CancelFunc

	managedHosts map[string]bool
	hostLock     sync.Mutex
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

func NewAdlist(url string, mux *dns.ServeMux, refreshInterval time.Duration) *Adlist {
	return &Adlist{
		url:             url,
		mux:             mux,
		handler:         New(fmt.Sprintf("adlist: %s", url)),
		managedHosts:    make(map[string]bool),
		refreshInterval: refreshInterval,
	}
}

func (r *Adlist) Refresh() error {
	resp, err := http.Get(r.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	newManagedHosts := make(map[string]bool)

	bodyStr := string(body)
	for _, line := range strings.Split(bodyStr, "\n") {
		hashPos := strings.Index(line, "#")
		if hashPos >= 0 {
			line = line[:hashPos]
		}
		line = strings.Trim(line, " \r\n\t")
		if line == "" {
			continue
		}

		split := strings.Split(strings.ReplaceAll(line, "\t", " "), " ")
		for _, host := range split {
			if host == "" || host == "." {
				continue
			}
			if hardcodeIgnoredAdHosts[host] {
				continue
			}
			if net.ParseIP(host) != nil {
				continue
			}
			newManagedHosts[host] = true
		}
	}

	r.hostLock.Lock()
	defer r.hostLock.Unlock()

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

	log.Printf("Adlist at %s refreshed, %d hosts managed (%d added, %d removed)", r.url, len(r.managedHosts), added, removed)

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
