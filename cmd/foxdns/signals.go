package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Doridian/foxDNS/server"
)

func handleSignals(srv *server.Server) {
	go handleTerm(srv)
	go handleRefresh(srv)
	go handleReload(srv)
}

func handleTerm(srv *server.Server) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Printf("Got signal, shutting down...")
	srv.Shutdown()
}

func handleReload(srv *server.Server) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	for {
		<-sigs
		log.Printf("Got reload signal, reloading...")
		reloadConfig()
	}
}
