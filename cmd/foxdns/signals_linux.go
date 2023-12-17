package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/FoxDenHome/foxdns/server"
)

func handleRefresh(srv *server.Server) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)
	for {
		<-sigs
		log.Printf("Got refreshing signal, refreshing...")
		for _, g := range generators {
			err := g.Refresh()
			if err != nil {
				log.Printf("Error refreshing generator: %v", err)
			}
		}
	}
}
