package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/FoxDenHome/foxdns/server"
)

func handleSignals(srv *server.Server) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Printf("Got signal, shutting down...")
	srv.Shutdown()
}
