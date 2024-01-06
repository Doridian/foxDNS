package util

import (
	"crypto"
	"crypto/rand"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var currentCookieSecret = make([]byte, 64)
var currentCookieSecretTime time.Time
var currentCookieSecretWriteLock sync.Mutex
var clientCookiePrefix = []byte("client")
var serverCookiePrefix = []byte("server")

func getCookieSecret() []byte {
	cookieSecretTimeCache := currentCookieSecretTime
	if time.Since(cookieSecretTimeCache) > time.Hour {
		currentCookieSecretWriteLock.Lock()
		if currentCookieSecretTime == cookieSecretTimeCache {
			_, err := rand.Read(currentCookieSecret)
			if err != nil {
				panic(err)
			}
			currentCookieSecretTime = time.Now()
		}
		currentCookieSecretWriteLock.Unlock()
	}
	return currentCookieSecret
}

func generateCookie(data ...[]byte) []byte {
	hash := crypto.SHA256.New()
	cookieSecret := getCookieSecret()
	hash.Write(cookieSecret[0:32])
	for _, d := range data {
		hash.Write(d)
	}
	return hash.Sum(cookieSecret[32:64])
}

func GenerateClientCookie(server string) []byte {
	return generateCookie(clientCookiePrefix, []byte(server))[:8]
}

func GenerateServerCookie(clientCookie string, wr dns.ResponseWriter) []byte {
	serverIp := ExtractIP(wr.LocalAddr())
	clientIp := ExtractIP(wr.RemoteAddr())
	return generateCookie(serverCookiePrefix, serverIp, clientIp, []byte(clientCookie))[:8]
}
