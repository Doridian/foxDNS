package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func handleRefresh() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)
	for {
		<-sigs
		log.Printf("Got refreshing signal, refreshing...")
		for _, l := range loaders {
			err := l.Refresh()
			if err != nil {
				log.Printf("Error refreshing loader: %v", err)
			}
		}
	}
}
