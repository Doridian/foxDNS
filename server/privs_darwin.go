//go:build darwin

package server

import (
	"log"
	"os"
	"strconv"
	"syscall"
)

func dropPrivs() {
	uid, _ := strconv.Atoi(os.Getenv("FOXDNS_UID"))
	gid, _ := strconv.Atoi(os.Getenv("FOXDNS_GID"))

	log.Printf("Startup IDs: UID = %d, GID = %d", syscall.Getuid(), syscall.Getgid())

	if gid > 0 {
		err := syscall.Setregid(gid, gid)
		if err != nil {
			log.Printf("Error dropping GID: %v", err)
		}
	}

	if uid > 0 {
		err := syscall.Setreuid(uid, uid)
		if err != nil {
			log.Printf("Error dropping UID: %v", err)
		}
	}

	log.Printf("Runtime IDs: UID = %d, GID = %d", syscall.Getuid(), syscall.Getgid())
}
