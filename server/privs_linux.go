//go:build linux

package server

import (
	"log"
	"os"
	"strconv"
	"syscall"
)

func dropPrivs() {
	uid, _ := strconv.Atoi(os.Getenv("PUID"))
	gid, _ := strconv.Atoi(os.Getenv("PGID"))

	log.Printf("Startup IDs: UID = %d, GID = %d", syscall.Getuid(), syscall.Getgid())

	if gid > 0 {
		err := syscall.Setresgid(gid, gid, gid)
		if err != nil {
			log.Printf("Error dropping GID: %v", err)
		}
	}

	if uid > 0 {
		err := syscall.Setresuid(uid, uid, uid)
		if err != nil {
			log.Printf("Error dropping UID: %v", err)
		}
	}

	log.Printf("Runtime IDs: UID = %d, GID = %d", syscall.Getuid(), syscall.Getgid())
}
